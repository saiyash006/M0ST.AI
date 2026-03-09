"""
Deobfuscation module — Detects and reverses common obfuscation techniques.

Implements detection and (where possible) reversal of:
- Control-flow flattening
- Opaque predicates
- Junk/dead code insertion
- Packer detection
- VM-based obfuscation / virtualization
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple


class DeobfuscationEngine:
    """
    Detects and mitigates obfuscation in binary code.
    Works on the graph store's CFG representation.
    """

    def analyze(self, graph_store, func_addr: int) -> Dict[str, Any]:
        """
        Run all deobfuscation checks on a function.

        Returns a report of detected obfuscation techniques
        and any simplifications applied.
        """
        blocks = graph_store.fetch_basic_blocks(func_addr)
        edges = graph_store.fetch_flow_edges(func_addr)
        block_insns = {
            bb: graph_store.fetch_block_instructions(bb) for bb in blocks
        }

        report = {
            "func_addr": func_addr,
            "obfuscation_detected": False,
            "techniques": [],
            "complexity_score": 0.0,
        }

        # Check for control-flow flattening
        cff = self._detect_control_flow_flattening(blocks, edges, block_insns)
        if cff["detected"]:
            report["obfuscation_detected"] = True
            report["techniques"].append(cff)

        # Check for opaque predicates
        opaque = self._detect_opaque_predicates(blocks, edges, block_insns)
        if opaque["detected"]:
            report["obfuscation_detected"] = True
            report["techniques"].append(opaque)

        # Check for junk code
        junk = self._detect_junk_code(blocks, block_insns)
        if junk["detected"]:
            report["obfuscation_detected"] = True
            report["techniques"].append(junk)

        # Check for packer signatures
        packer = self._detect_packer_signatures(blocks, block_insns)
        if packer["detected"]:
            report["obfuscation_detected"] = True
            report["techniques"].append(packer)

        # Check for VM-based obfuscation
        vm_obf = self._detect_virtualization(blocks, block_insns)
        if vm_obf["detected"]:
            report["obfuscation_detected"] = True
            report["techniques"].append(vm_obf)

        # Compute obfuscation complexity score
        report["complexity_score"] = self._compute_complexity_score(
            blocks, edges, block_insns, report["techniques"]
        )

        return report

    def simplify(self, graph_store, func_addr: int) -> Dict[str, Any]:
        """
        Attempt to simplify obfuscated CFG.

        Removes detected junk code and resolves opaque predicates
        where possible.
        """
        report = self.analyze(graph_store, func_addr)
        modifications = []

        for technique in report.get("techniques", []):
            if technique["type"] == "junk_code":
                removed = self._remove_junk_instructions(
                    graph_store, func_addr, technique.get("junk_blocks", [])
                )
                if removed:
                    modifications.append({
                        "action": "removed_junk",
                        "count": removed,
                    })

            elif technique["type"] == "opaque_predicate":
                resolved = self._resolve_opaque_predicates(
                    graph_store, func_addr, technique.get("suspect_branches", [])
                )
                if resolved:
                    modifications.append({
                        "action": "resolved_opaque_predicates",
                        "count": resolved,
                    })

        report["modifications"] = modifications
        return report

    # ── Detection Methods ──────────────────────────────────────────────

    def _detect_control_flow_flattening(
        self,
        blocks: List[int],
        edges: List[Tuple[int, int]],
        block_insns: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Detect control-flow flattening (CFF).

        Indicators:
        - A dispatcher block that many blocks jump back to
        - State variable loaded/compared in the dispatcher
        - Unusually flat CFG (many blocks at same depth)
        """
        result = {"type": "control_flow_flattening", "detected": False, "details": {}}

        if len(blocks) < 5:
            return result

        # Count incoming edges per block
        in_degree: Dict[int, int] = {b: 0 for b in blocks}
        out_degree: Dict[int, int] = {b: 0 for b in blocks}
        for src, dst in edges:
            if dst in in_degree:
                in_degree[dst] += 1
            if src in out_degree:
                out_degree[src] += 1

        # Find potential dispatcher: high in-degree block with conditional jump
        max_in = max(in_degree.values()) if in_degree else 0
        if max_in < 3:
            return result

        dispatchers = [
            b for b, deg in in_degree.items()
            if deg >= max(3, len(blocks) // 3)
        ]

        if not dispatchers:
            return result

        # Check if dispatcher contains comparison (state variable check)
        for disp in dispatchers:
            insns = block_insns.get(disp, [])
            has_cmp = any(
                (insn.get("mnemonic") or "").lower() in ("cmp", "test", "sub")
                for insn in insns
            )
            has_jump = any(
                (insn.get("mnemonic") or "").lower().startswith("j")
                and (insn.get("mnemonic") or "").lower() != "jmp"
                for insn in insns
            )
            if has_cmp and has_jump:
                result["detected"] = True
                result["details"] = {
                    "dispatcher_block": disp,
                    "in_degree": in_degree[disp],
                    "total_blocks": len(blocks),
                }
                break

        return result

    def _detect_opaque_predicates(
        self,
        blocks: List[int],
        edges: List[Tuple[int, int]],
        block_insns: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Detect opaque predicates — branches that always take the same path.

        Indicators:
        - Constant comparison values
        - Algebraic identities (x*x >= 0, x^x == 0)
        - One branch target is unreachable
        """
        result = {
            "type": "opaque_predicate",
            "detected": False,
            "suspect_branches": [],
        }

        # Build successor map
        succs: Dict[int, List[int]] = {b: [] for b in blocks}
        for src, dst in edges:
            if src in succs:
                succs[src].append(dst)

        for bb in blocks:
            insns = block_insns.get(bb, [])
            if not insns:
                continue

            last = insns[-1]
            mnem = (last.get("mnemonic") or "").lower()
            if not mnem.startswith("j") or mnem in ("jmp",):
                continue

            if len(succs.get(bb, [])) != 2:
                continue

            # Look for algebraic identity patterns
            for insn in insns:
                ins_mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                if len(ops) >= 2:
                    # xor reg, reg (always 0)
                    if ins_mnem == "xor" and ops[0].lower() == ops[1].lower():
                        result["detected"] = True
                        result["suspect_branches"].append({
                            "block": bb,
                            "pattern": "xor_identity",
                            "instruction": f"{ins_mnem} {', '.join(ops)}",
                        })
                    # cmp with immediate constants that are always true/false
                    if ins_mnem == "cmp" and self._is_constant(ops[0]) and self._is_constant(ops[1]):
                        result["detected"] = True
                        result["suspect_branches"].append({
                            "block": bb,
                            "pattern": "constant_comparison",
                            "instruction": f"{ins_mnem} {', '.join(ops)}",
                        })

        return result

    def _detect_junk_code(
        self,
        blocks: List[int],
        block_insns: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Detect junk/dead code insertion.

        Indicators:
        - NOP sleds
        - Instructions that cancel each other (push/pop same reg)
        - Blocks with only nops
        """
        result = {"type": "junk_code", "detected": False, "junk_blocks": [], "details": {}}

        total_insns = 0
        nop_count = 0
        cancel_pairs = 0

        for bb in blocks:
            insns = block_insns.get(bb, [])
            all_nops = True
            bb_nops = 0

            for i, insn in enumerate(insns):
                total_insns += 1
                mnem = (insn.get("mnemonic") or "").lower()

                if mnem in ("nop", "fnop", "xchg") or mnem.startswith("nop"):
                    nop_count += 1
                    bb_nops += 1
                else:
                    all_nops = False

                # Detect push/pop cancellation
                if mnem == "push" and i + 1 < len(insns):
                    next_mnem = (insns[i + 1].get("mnemonic") or "").lower()
                    next_ops = insns[i + 1].get("operands") or []
                    ops = insn.get("operands") or []
                    if (
                        next_mnem == "pop"
                        and ops
                        and next_ops
                        and ops[0].lower() == next_ops[0].lower()
                    ):
                        cancel_pairs += 1

            if all_nops and len(insns) > 0:
                result["junk_blocks"].append(bb)

        if total_insns > 0:
            nop_ratio = nop_count / total_insns
            if nop_ratio > 0.15 or cancel_pairs > 2 or len(result["junk_blocks"]) > 0:
                result["detected"] = True
                result["details"] = {
                    "nop_ratio": round(nop_ratio, 3),
                    "cancel_pairs": cancel_pairs,
                    "nop_blocks": len(result["junk_blocks"]),
                }

        return result

    def _detect_packer_signatures(
        self,
        blocks: List[int],
        block_insns: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Detect common packer patterns.

        Indicators:
        - Self-modifying code patterns (write to code section)
        - High entropy instruction sequences
        - Small number of functions with large single blocks
        """
        result = {"type": "packer", "detected": False, "details": {}}

        # Check for large single-block "functions" (common in packed binaries)
        if len(blocks) == 1:
            insns = block_insns.get(blocks[0], [])
            if len(insns) > 200:
                result["detected"] = True
                result["details"]["large_single_block"] = len(insns)

        # Check for write-execute patterns
        for bb in blocks:
            insns = block_insns.get(bb, [])
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                # VirtualProtect / mprotect calls
                if mnem in ("call", "bl") and ops:
                    target = ops[0].lower()
                    if any(p in target for p in ("virtualprotect", "mprotect", "virtualalloc")):
                        result["detected"] = True
                        result["details"]["memory_protection_change"] = True

        return result

    def _detect_virtualization(
        self,
        blocks: List[int],
        block_insns: Dict[int, List[Dict]],
    ) -> Dict[str, Any]:
        """
        Detect VM-based obfuscation / code virtualization.

        Indicators:
        - Handler dispatch loop pattern
        - Bytecode fetch-decode-execute cycle
        - Large switch-like dispatcher
        """
        result = {"type": "virtualization", "detected": False, "details": {}}

        # Look for characteristic VM handler patterns
        for bb in blocks:
            insns = block_insns.get(bb, [])
            if len(insns) < 3:
                continue

            # Pattern: load byte from pointer, use as index
            has_byte_load = False
            has_table_lookup = False
            has_indirect_jump = False

            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops_str = " ".join(insn.get("operands") or []).lower()

                if mnem in ("movzx", "movsx") and "byte" in ops_str:
                    has_byte_load = True
                if re.search(r"\[.*\+.*\*.*\]", ops_str):
                    has_table_lookup = True
                if mnem == "jmp" and ("[" in ops_str or "r" in ops_str):
                    has_indirect_jump = True

            if has_byte_load and has_table_lookup and has_indirect_jump:
                result["detected"] = True
                result["details"]["vm_handler_block"] = bb

        return result

    # ── Simplification Methods ─────────────────────────────────────────

    def _remove_junk_instructions(
        self,
        graph_store,
        func_addr: int,
        junk_blocks: List[int],
    ) -> int:
        """Mark junk blocks in the graph store. Returns count."""
        count = 0
        for bb in junk_blocks:
            try:
                graph_store.set_function_properties(func_addr, {
                    f"junk_block_{bb:x}": True,
                })
                count += 1
            except Exception:
                pass
        return count

    def _resolve_opaque_predicates(
        self,
        graph_store,
        func_addr: int,
        suspect_branches: List[Dict],
    ) -> int:
        """Mark opaque predicates. Returns count resolved."""
        count = 0
        for branch in suspect_branches:
            try:
                bb = branch.get("block")
                if bb is not None:
                    graph_store.mark_flow_edge_suspect(bb, bb)
                    count += 1
            except Exception:
                pass
        return count

    # ── Helpers ────────────────────────────────────────────────────────

    def _is_constant(self, operand: str) -> bool:
        """Check if an operand is a constant value."""
        if not isinstance(operand, str):
            return False
        operand = operand.strip()
        try:
            if operand.startswith("0x") or operand.startswith("-0x"):
                int(operand, 16)
                return True
            int(operand)
            return True
        except (ValueError, TypeError):
            return False

    def _compute_complexity_score(
        self,
        blocks: List[int],
        edges: List[Tuple[int, int]],
        block_insns: Dict[int, List[Dict]],
        techniques: List[Dict],
    ) -> float:
        """
        Compute an obfuscation complexity score (0.0 - 1.0).

        Higher scores indicate more likely obfuscation.
        """
        score = 0.0

        # Base CFG complexity
        if blocks:
            edge_ratio = len(edges) / max(len(blocks), 1)
            if edge_ratio > 3.0:
                score += 0.2

        # Technique scores
        for tech in techniques:
            if tech.get("detected"):
                t = tech.get("type", "")
                if t == "control_flow_flattening":
                    score += 0.3
                elif t == "opaque_predicate":
                    score += 0.15
                elif t == "junk_code":
                    score += 0.1
                elif t == "packer":
                    score += 0.3
                elif t == "virtualization":
                    score += 0.4

        return min(score, 1.0)
