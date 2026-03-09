import re
from typing import Dict, List, Optional, Set, Tuple

from core.capabilities import Capability


class HeuristicsAgent:
    """
    Applies classical reverse engineering heuristics.
    Responsibilities:
    - Identify loop constructs, jump tables, prologues, and epilogues.
    - Detect crypto patterns based on opcode sequences.
    - Infer switch-case structures.
    - Enhance CFG fidelity without AI involvement.
    - Update graph DB with heuristic-derived facts.
    """
    CAPABILITIES = {Capability.STATIC_READ}

    def __init__(self, graph_store, bus=None):
        self.g = graph_store
        self.bus = bus

    def run(self):
        functions = self.g.fetch_functions()
        for func in functions:
            func_addr = func.get("addr")
            if func_addr is None:
                continue
            self._analyze_function(func_addr)

        if self.bus is not None:
            self.bus.publish(
                "HEURISTICS_COMPLETE", {"function_count": len(functions)}
            )

    # ---------------------------
    # Function Analysis
    # ---------------------------

    def _analyze_function(self, func_addr: int):
        blocks = self.g.fetch_basic_blocks(func_addr)
        if not blocks:
            return

        edges = self.g.fetch_flow_edges(func_addr)
        entry = func_addr if func_addr in blocks else min(blocks)

        preds, succs = self._build_cfg(blocks, edges)
        dominators = self._compute_dominators(blocks, preds, entry)
        loops = self._find_loops(edges, preds, dominators)

        block_insns = {
            bb: self.g.fetch_block_instructions(bb) for bb in blocks
        }

        loop_depths = self._compute_loop_depths(loops)
        for header, info in loops.items():
            loop_body = sorted(info["body"])
            back_edges = sorted(info["back_edges"])
            crypto_ct = self._detect_constant_time_crypto(loop_body, block_insns)
            self.g.mark_loop_header(
                header,
                loop_body=loop_body,
                back_edges=back_edges,
                loop_depth=loop_depths.get(header, 1),
                crypto_constant_time=crypto_ct,
            )

        props = {}
        props.update(self._detect_pointer_arithmetic(block_insns))
        props.update(self._detect_stack_frame(block_insns.get(entry, [])))
        props.update(self._classify_function(block_insns))

        switch_hits = self._detect_switch_tables(blocks, block_insns)
        for header_bb, cases in switch_hits:
            self.g.set_switch_info(func_addr, header_bb, cases)

        if props:
            self.g.set_function_properties(func_addr, props)

    # ---------------------------
    # CFG + Dominators
    # ---------------------------

    def _build_cfg(
        self, blocks: List[int], edges: List[Tuple[int, int]]
    ) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
        preds = {b: set() for b in blocks}
        succs = {b: set() for b in blocks}
        for src, dst in edges:
            if src in succs and dst in preds:
                succs[src].add(dst)
                preds[dst].add(src)
        return preds, succs

    def _compute_dominators(
        self, blocks: List[int], preds: Dict[int, Set[int]], entry: int
    ) -> Dict[int, Set[int]]:
        all_nodes = set(blocks)
        dom = {b: set(all_nodes) for b in blocks}
        dom[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for b in blocks:
                if b == entry:
                    continue
                if not preds[b]:
                    new_dom = {b}
                else:
                    new_dom = set.intersection(*(dom[p] for p in preds[b]))
                    new_dom.add(b)
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True
        return dom

    def _find_loops(
        self,
        edges: List[Tuple[int, int]],
        preds: Dict[int, Set[int]],
        dominators: Dict[int, Set[int]],
    ) -> Dict[int, Dict[str, Set[int]]]:
        loops: Dict[int, Dict[str, Set[int]]] = {}
        for src, dst in edges:
            if dst in dominators.get(src, set()):
                header = dst
                loop_body = self._natural_loop(src, dst, preds)
                if header not in loops:
                    loops[header] = {"body": set(), "back_edges": set()}
                loops[header]["body"].update(loop_body)
                loops[header]["back_edges"].add(src)
        return loops

    def _natural_loop(
        self, src: int, header: int, preds: Dict[int, Set[int]]
    ) -> Set[int]:
        loop_nodes = {header, src}
        stack = [src]
        while stack:
            node = stack.pop()
            for p in preds.get(node, set()):
                if p not in loop_nodes:
                    loop_nodes.add(p)
                    if p != header:
                        stack.append(p)
        return loop_nodes

    def _compute_loop_depths(
        self, loops: Dict[int, Dict[str, Set[int]]]
    ) -> Dict[int, int]:
        depths = {h: 1 for h in loops}
        for h, info in loops.items():
            depth = 1
            for other, other_info in loops.items():
                if other != h and h in other_info["body"]:
                    depth += 1
            depths[h] = depth
        return depths

    # ---------------------------
    # Heuristics
    # ---------------------------

    def _detect_constant_time_crypto(
        self, loop_body: List[int], block_insns: Dict[int, List[Dict]]
    ) -> bool:
        crypto_ops = {
            "xor", "xora", "and", "or", "not", "rol", "ror",
            "shl", "shr", "sar", "add", "sub", "adc", "sbb",
        }
        branch_ops = {"jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jb", "jc"}
        call_ops = {"call", "bl", "blr"}

        total = 0
        crypto = 0
        branches = 0
        calls = 0
        for bb in loop_body:
            for insn in block_insns.get(bb, []):
                mnem = (insn.get("mnemonic") or "").lower()
                if not mnem:
                    continue
                total += 1
                if mnem in crypto_ops:
                    crypto += 1
                if mnem.startswith("j") or mnem in branch_ops or mnem.startswith("b."):
                    branches += 1
                if mnem in call_ops:
                    calls += 1

        if total < 6:
            return False
        crypto_ratio = crypto / max(total, 1)
        if calls > 0:
            return False
        if crypto_ratio >= 0.4 and branches <= 2:
            return True
        return False

    def _detect_pointer_arithmetic(
        self, block_insns: Dict[int, List[Dict]]
    ) -> Dict:
        examples = []
        pattern = re.compile(r"\[.*[+\-*].*\]")
        for insns in block_insns.values():
            for insn in insns:
                ops = insn.get("operands") or []
                for op in ops:
                    if pattern.search(op) or "ptr" in op.lower():
                        examples.append(op)
                        if len(examples) >= 5:
                            break
                if len(examples) >= 5:
                    break
            if len(examples) >= 5:
                break

        return {
            "pointer_arith": bool(examples),
            "pointer_arith_examples": examples,
        }

    def _detect_stack_frame(self, entry_insns: List[Dict]) -> Dict:
        frame_pointer = False
        stack_alloc = None
        prologue = []

        for insn in entry_insns[:8]:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []
            prologue.append(mnem)

            if mnem == "enter" and ops:
                frame_pointer = True
                stack_alloc = self._parse_imm(ops[0])
            if mnem == "push" and ops and ops[0].lower() in {"rbp", "ebp", "fp"}:
                frame_pointer = True
            if mnem == "mov" and len(ops) >= 2:
                dst = ops[0].lower()
                src = ops[1].lower()
                if dst in {"rbp", "ebp", "fp"} and src in {"rsp", "esp", "sp"}:
                    frame_pointer = True
            if mnem == "sub" and len(ops) >= 2:
                dst = ops[0].lower()
                if dst in {"rsp", "esp", "sp"}:
                    stack_alloc = self._parse_imm(ops[1])

        shape = "unknown"
        if frame_pointer and stack_alloc:
            shape = "frame_pointer+alloc"
        elif frame_pointer:
            shape = "frame_pointer_only"
        elif stack_alloc:
            shape = "stack_alloc_only"

        return {
            "stack_frame_shape": shape,
            "stack_frame_size": stack_alloc,
            "uses_frame_pointer": frame_pointer,
        }

    def _classify_function(self, block_insns: Dict[int, List[Dict]]) -> Dict:
        mnems = []
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem:
                    mnems.append(mnem)

        classes = []
        if self._is_memcpy_like(mnems):
            classes.append("memcpy_like")
        if self._is_memset_like(mnems):
            classes.append("memset_like")

        if not classes:
            return {}
        return {"function_classification": classes}

    def _is_memcpy_like(self, mnems: List[str]) -> bool:
        for m in mnems:
            if "movs" in m:
                return True
            if m.startswith("rep") and "movs" in m:
                return True
        return False

    def _is_memset_like(self, mnems: List[str]) -> bool:
        for m in mnems:
            if "stos" in m:
                return True
            if m.startswith("rep") and "stos" in m:
                return True
        return False

    def _parse_imm(self, value: str):
        if not isinstance(value, str):
            return None
        v = value.strip()
        try:
            if v.startswith("0x") or v.startswith("-0x"):
                return int(v, 16)
            return int(v, 10)
        except Exception:
            return None

    def _detect_switch_tables(
        self, blocks: List[int], block_insns: Dict[int, List[Dict]]
    ) -> List[Tuple[int, List[int]]]:
        hits: List[Tuple[int, List[int]]] = []
        for bb in blocks:
            insns = block_insns.get(bb, [])
            if not insns:
                continue
            last = insns[-1]
            mnem = (last.get("mnemonic") or "").lower()
            if mnem not in {"jmp", "br", "bx"}:
                continue
            ops = last.get("operands") or []
            if not ops:
                continue
            if not self._looks_like_indirect_table(ops[0]):
                continue

            cases = self._extract_table_constants(insns)
            if len(cases) < 3:
                continue
            if not self._is_contiguous_cases(cases):
                continue

            hits.append((bb, cases))
        return hits

    def _looks_like_indirect_table(self, op: str) -> bool:
        if not isinstance(op, str):
            return False
        return bool(re.search(r"\[.*\+.*\*.*\]", op))

    def _extract_table_constants(self, insns: List[Dict]) -> List[int]:
        cases = []
        for insn in insns:
            ops = insn.get("operands") or []
            for op in ops:
                imm = self._parse_imm(op) if isinstance(op, str) else None
                if imm is not None:
                    cases.append(imm)
        return cases

    def _is_contiguous_cases(self, cases: List[int]) -> bool:
        if len(cases) < 3:
            return False
        cases_sorted = sorted(set(cases))
        if len(cases_sorted) < 3:
            return False
        for i in range(1, len(cases_sorted)):
            if cases_sorted[i] != cases_sorted[i - 1] + 1:
                return False
        return True
