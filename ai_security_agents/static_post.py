"""
Post-processing passes for static analysis results.
Operates on the graph store to clean up and enrich CFG data.
"""

from typing import Dict, List, Set, Tuple


class StaticPost:

    @staticmethod
    def remove_unreachable_blocks(graph_store, func_addr: int) -> int:
        """
        Remove basic blocks not reachable from the function entry point.
        Returns the number of blocks removed.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        if not blocks:
            return 0

        edges = graph_store.fetch_flow_edges(func_addr)
        entry = func_addr if func_addr in blocks else min(blocks)

        # BFS from entry
        reachable: Set[int] = set()
        queue = [entry]
        succs: Dict[int, List[int]] = {b: [] for b in blocks}
        for s, d in edges:
            if s in succs:
                succs[s].append(d)

        while queue:
            node = queue.pop(0)
            if node in reachable:
                continue
            reachable.add(node)
            for nxt in succs.get(node, []):
                if nxt not in reachable:
                    queue.append(nxt)

        unreachable = set(blocks) - reachable
        for bb in unreachable:
            for s, d in edges:
                if s == bb or d == bb:
                    graph_store.remove_flow_edge(s, d)

        return len(unreachable)

    @staticmethod
    def fold_linear_blocks(graph_store, func_addr: int) -> int:
        """
        Identify linear chains (single pred -> single succ) and mark them.
        Returns the number of linear chains found.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        edges = graph_store.fetch_flow_edges(func_addr)

        preds: Dict[int, List[int]] = {b: [] for b in blocks}
        succs: Dict[int, List[int]] = {b: [] for b in blocks}
        for s, d in edges:
            if s in succs:
                succs[s].append(d)
            if d in preds:
                preds[d].append(s)

        chains = 0
        visited: Set[int] = set()
        for bb in blocks:
            if bb in visited:
                continue
            chain = [bb]
            current = bb
            while True:
                s = succs.get(current, [])
                if len(s) != 1:
                    break
                nxt = s[0]
                p = preds.get(nxt, [])
                if len(p) != 1 or p[0] != current:
                    break
                if nxt in visited:
                    break
                chain.append(nxt)
                current = nxt

            if len(chain) > 1:
                chains += 1
                for node in chain:
                    visited.add(node)

        return chains

    @staticmethod
    def detect_switch_tables(graph_store, func_addr: int) -> List[Tuple[int, List[int]]]:
        """
        Detect indirect jump tables (switch-case) in a function.
        Returns list of (header_bb, [case_targets]).
        """
        import re

        blocks = graph_store.fetch_basic_blocks(func_addr)
        results = []

        for bb in blocks:
            insns = graph_store.fetch_block_instructions(bb)
            if not insns:
                continue
            last = insns[-1]
            mnem = (last.get("mnemonic") or "").lower()
            if mnem not in {"jmp", "br", "bx"}:
                continue
            ops = last.get("operands") or []
            if not ops:
                continue
            if not re.search(r"\[.*\+.*\*.*\]", ops[0]):
                continue

            edges = graph_store.fetch_flow_edges_from(bb)
            targets = [d for _, d in edges]
            if len(targets) >= 3:
                results.append((bb, targets))
                graph_store.set_switch_info(func_addr, bb, targets)

        return results

    @staticmethod
    def infer_prologue_epilogue(graph_store, func_addr: int) -> Dict:
        """
        Analyze instruction patterns at function entry/exit to identify
        standard prologue and epilogue sequences.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        if not blocks:
            return {"prologue": False, "epilogue": False}

        entry = func_addr if func_addr in blocks else min(blocks)
        entry_insns = graph_store.fetch_block_instructions(entry)

        prologue = False
        epilogue = False

        for insn in entry_insns[:4]:
            mnem = (insn.get("mnemonic") or "").lower()
            ops = insn.get("operands") or []
            if mnem == "push" and ops and ops[0].lower() in {"rbp", "ebp", "fp"}:
                prologue = True
            if mnem == "mov" and len(ops) >= 2:
                if ops[0].lower() in {"rbp", "ebp"} and ops[1].lower() in {"rsp", "esp"}:
                    prologue = True

        for bb in blocks:
            insns = graph_store.fetch_block_instructions(bb)
            if not insns:
                continue
            last_mnem = (insns[-1].get("mnemonic") or "").lower()
            if last_mnem in {"ret", "retq", "retn"}:
                for insn in insns[-3:]:
                    m = (insn.get("mnemonic") or "").lower()
                    o = insn.get("operands") or []
                    if m == "pop" and o and o[0].lower() in {"rbp", "ebp", "fp"}:
                        epilogue = True
                    if m == "leave":
                        epilogue = True

        result = {"prologue": prologue, "epilogue": epilogue}
        graph_store.set_function_properties(func_addr, {
            "has_prologue": prologue,
            "has_epilogue": epilogue,
        })
        return result
