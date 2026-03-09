"""
Symbol Recovery pipeline for M0ST.

Combines GNN embeddings, transformer-style sequence analysis,
and LLM reasoning to recover stripped symbol information:
    - function name prediction
    - variable name recovery
    - argument type inference
    - struct layout recovery
"""

import re
from typing import Any, Dict, List, Optional


class SymbolRecoveryEngine:
    """
    Recovers stripped symbols using a multi-model approach:
        1. GNN embeddings for structural matching
        2. Sequence analysis for instruction patterns
        3. LLM reasoning as fallback for complex cases
    """

    def __init__(self, graph_store, embedding_engine=None, llm_engine=None):
        self.g = graph_store
        self.embeddings = embedding_engine
        self.llm = llm_engine

    # ── Function Name Prediction ───────────────────────────────────────────

    def predict_function_name(self, func_addr: int) -> Dict[str, Any]:
        """Predict a meaningful name for a stripped function."""
        # Stage 1: Heuristic-based naming from call targets
        heuristic_name = self._heuristic_name(func_addr)

        # Stage 2: Embedding similarity (if engine available)
        embedding_name = None
        if self.embeddings:
            try:
                similar = self.embeddings.find_similar_functions(func_addr, top_k=3)
                if similar:
                    best_addr, score = similar[0]
                    if score > 0.85:
                        func = self.g.get_function(best_addr)
                        if func and not func.get("name", "").startswith("sub_"):
                            embedding_name = {
                                "name": f"similar_to_{func['name']}",
                                "confidence": score * 0.8,
                                "source": "embedding_similarity",
                            }
            except Exception:
                pass

        # Stage 3: LLM-based naming (if available)
        llm_name = None
        if self.llm and self.llm.client:
            try:
                context = self._gather_function_context(func_addr)
                prompt = self.llm.build_prompt(
                    task="predict_function_name",
                    instruction=(
                        "Analyze this function and suggest a descriptive name. "
                        'Return JSON: {"name": str, "confidence": float, "reasoning": str}'
                    ),
                    **context,
                )
                llm_name = self.llm.query_json(prompt)
            except Exception:
                pass

        # Select best result
        candidates = []
        if llm_name and "name" in llm_name and "error" not in llm_name:
            candidates.append(llm_name)
        if embedding_name:
            candidates.append(embedding_name)
        if heuristic_name:
            candidates.append(heuristic_name)

        if candidates:
            return max(candidates, key=lambda c: c.get("confidence", 0))
        return {"name": f"sub_{func_addr:x}", "confidence": 0.0, "source": "fallback"}

    # ── Variable Name Recovery ─────────────────────────────────────────────

    def recover_variable_names(self, func_addr: int) -> List[Dict[str, Any]]:
        """Recover meaningful variable names for a function."""
        blocks = self.g.fetch_basic_blocks(func_addr)
        registers = self._extract_registers(blocks)

        if self.llm and self.llm.client:
            try:
                context = self._gather_function_context(func_addr)
                prompt = self.llm.build_prompt(
                    task="recover_variable_names",
                    instruction=(
                        "Analyze the registers and stack slots used in this function. "
                        "Suggest descriptive variable names. Return JSON: "
                        '{"variables": [{"original": str, "suggested": str, '
                        '"type_hint": str, "reasoning": str}]}'
                    ),
                    **context,
                )
                result = self.llm.query_json(prompt)
                if "variables" in result:
                    return result["variables"]
            except Exception:
                pass

        # Fallback: return registers as-is
        return [{"original": r, "suggested": r, "type_hint": "register"}
                for r in sorted(registers)]

    # ── Argument Type Inference ────────────────────────────────────────────

    def infer_argument_types(self, func_addr: int) -> Dict[str, Any]:
        """Infer argument types for a function."""
        if self.llm and self.llm.client:
            try:
                context = self._gather_function_context(func_addr)
                prompt = self.llm.build_prompt(
                    task="infer_argument_types",
                    instruction=(
                        "Analyze this function and infer its argument types and return type. "
                        'Return JSON: {"parameters": [{"name": str, "type": str}], '
                        '"return_type": str, "reasoning": str}'
                    ),
                    **context,
                )
                return self.llm.query_json(prompt)
            except Exception:
                pass

        return {"parameters": [], "return_type": "unknown", "reasoning": "No inference available"}

    # ── Struct Layout Recovery ─────────────────────────────────────────────

    def recover_struct_layout(self, func_addr: int) -> List[Dict[str, Any]]:
        """Attempt to recover struct/class layouts from memory access patterns."""
        blocks = self.g.fetch_basic_blocks(func_addr)
        access_patterns = self._extract_memory_accesses(blocks)

        if not access_patterns:
            return []

        if self.llm and self.llm.client:
            try:
                context = self._gather_function_context(func_addr)
                context["extra"] = f"\n[MEMORY_ACCESSES]: {access_patterns}"
                prompt = self.llm.build_prompt(
                    task="recover_struct_layout",
                    instruction=(
                        "Analyze the memory access patterns and reconstruct potential "
                        "struct layouts. Return JSON: "
                        '{"structs": [{"name": str, "size": int, '
                        '"fields": [{"offset": int, "name": str, "type": str, "size": int}]}]}'
                    ),
                    **context,
                )
                result = self.llm.query_json(prompt)
                if "structs" in result:
                    return result["structs"]
            except Exception:
                pass

        # Fallback: group accesses by base register
        return self._heuristic_struct_recovery(access_patterns)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _heuristic_name(self, func_addr: int) -> Optional[Dict[str, Any]]:
        """Simple heuristic naming based on called functions."""
        blocks = self.g.fetch_basic_blocks(func_addr)
        calls = []
        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in ("call", "bl", "blr"):
                    ops = insn.get("operands", [])
                    if ops:
                        name = str(ops[0])
                        for prefix in ("sym.imp.", "sym.", "plt."):
                            if name.startswith(prefix):
                                name = name[len(prefix):]
                        calls.append(name)

        if not calls:
            return None
        if len(calls) == 1:
            return {"name": f"wrapper_{calls[0]}", "confidence": 0.4, "source": "heuristic"}
        return {"name": f"sub_{func_addr:x}", "confidence": 0.2, "source": "heuristic"}

    def _gather_function_context(self, func_addr: int) -> Dict[str, Any]:
        """Gather context for LLM prompting."""
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        disasm_lines = []
        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            disasm_lines.append(f"; Block 0x{bb:x}")
            for insn in insns:
                addr = insn.get("addr", 0)
                mnem = insn.get("mnemonic", "???")
                ops = ", ".join(str(o) for o in insn.get("operands", []))
                disasm_lines.append(f"  0x{addr:x}: {mnem} {ops}")

        gnn_emb = None
        if self.embeddings:
            try:
                gnn_emb = self.embeddings.get_embedding_vector(func_addr)
            except Exception:
                pass

        return {
            "disassembly": "\n".join(disasm_lines),
            "metadata": {
                "func_addr": f"0x{func_addr:x}",
                "block_count": len(blocks),
                "edge_count": len(edges),
            },
            "gnn_embedding": gnn_emb,
        }

    def _extract_registers(self, blocks: List[int]) -> set:
        """Extract unique register references from blocks."""
        regs = set()
        reg_pattern = re.compile(
            r"\b(r[abcd]x|r[bs]p|r[sd]i|r\d+|e[abcd]x|e[bs]p|e[sd]i)\b",
            re.IGNORECASE,
        )
        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            for insn in insns:
                for op in insn.get("operands", []):
                    for r in reg_pattern.findall(str(op)):
                        regs.add(r.lower())
        return regs

    def _extract_memory_accesses(self, blocks: List[int]) -> List[Dict]:
        """Extract structured memory access info from instructions."""
        accesses = []
        pattern = re.compile(r"\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]")
        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                for op in insn.get("operands", []):
                    match = pattern.search(str(op))
                    if match:
                        base = match.group(1)
                        try:
                            offset = int(match.group(2), 0)
                        except ValueError:
                            continue
                        accesses.append({
                            "base": base, "offset": offset,
                            "mnemonic": mnem, "addr": insn.get("addr", 0),
                        })
        return accesses

    def _heuristic_struct_recovery(self, accesses: List[Dict]) -> List[Dict]:
        """Group memory accesses by base register to infer struct fields."""
        from collections import defaultdict
        groups = defaultdict(set)
        for acc in accesses:
            groups[acc["base"]].add(acc["offset"])

        structs = []
        for base, offsets in groups.items():
            if len(offsets) >= 3:
                sorted_offsets = sorted(offsets)
                fields = []
                for i, off in enumerate(sorted_offsets):
                    next_off = sorted_offsets[i + 1] if i + 1 < len(sorted_offsets) else off + 8
                    field_size = min(next_off - off, 8)
                    fields.append({
                        "offset": off,
                        "name": f"field_{off:x}",
                        "type": "unknown",
                        "size": max(field_size, 1),
                    })
                structs.append({
                    "name": f"struct_{base}",
                    "size": max(offsets) + 8,
                    "fields": fields,
                })
        return structs
