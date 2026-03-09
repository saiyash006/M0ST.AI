"""
LLM Semantic Agent — AI-powered semantic analysis.

Replaces the legacy heuristics-based SemanticAgent with LLM + GNN
embedding-driven reasoning for function naming, variable naming,
type inference, behavior summarization, and code annotation.
"""

import json
import re
from typing import Any, Dict, List, Optional

from core.capabilities import Capability


class LLMSemanticAgent:
    """
    AI-powered semantic reasoning agent.

    Uses LLM + GNN embeddings to:
    - Infer function names
    - Suggest variable names
    - Infer types
    - Summarize function behavior
    - Infer algorithmic intent
    - Annotate code
    - Detect vulnerabilities

    Replaces old heuristic-based reasoning with LLM calls augmented
    by structural GNN embeddings.
    """

    CAPABILITIES = {Capability.SEMANTIC_REASON, Capability.STATIC_READ}

    def __init__(
        self,
        graph_store,
        llm_agent=None,
        graph_agent=None,
        pseudocode_agent=None,
    ):
        self.g = graph_store
        self.llm = llm_agent
        self.gnn = graph_agent
        self.pseudo = pseudocode_agent

    # ── Public API ─────────────────────────────────────────────────────────

    def explain(self, func_addr: int, level: str = "medium") -> Dict[str, Any]:
        """
        Generate semantic explanation at the requested detail level.
        Falls back to classical heuristics if LLM is unavailable.
        """
        if self.llm is not None and self.llm.client is not None:
            return self._explain_with_llm(func_addr, level)
        return self._explain_classical(func_addr, level)

    def infer_function_name(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return {"name": self._classical_name(func_addr), "confidence": 0.3, "reasoning": "Classical heuristic"}
        return self.llm.infer_function_name(**context)

    def infer_variable_names(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return {"variables": self._classical_variables(func_addr)}
        return self.llm.infer_variable_names(**context)

    def infer_types(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return {"parameters": [], "return_type": "unknown", "locals": [], "reasoning": "No LLM available"}
        return self.llm.infer_types(**context)

    def summarize_function(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return self._classical_summary(func_addr)
        return self.llm.summarize_function(**context)

    def annotate_function(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return {"annotated_code": context.get("pseudocode", "// No pseudocode available")}
        return self.llm.annotate_code(
            pseudocode=context.get("pseudocode", ""),
            disassembly=context.get("disassembly", ""),
            metadata=context.get("metadata"),
        )

    def detect_vulnerabilities(self, func_addr: int) -> Dict[str, Any]:
        context = self._gather_context(func_addr)
        if self.llm is None or self.llm.client is None:
            return {"vulnerabilities": self._classical_vulns(func_addr)}
        return self.llm.detect_vulnerabilities(
            disassembly=context.get("disassembly", ""),
            pseudocode=context.get("pseudocode", ""),
            metadata=context.get("metadata"),
        )

    def full_analysis(self, func_addr: int) -> Dict[str, Any]:
        return {
            "func_addr": func_addr,
            "name_inference": self.infer_function_name(func_addr),
            "variable_inference": self.infer_variable_names(func_addr),
            "type_inference": self.infer_types(func_addr),
            "summary": self.summarize_function(func_addr),
            "vulnerabilities": self.detect_vulnerabilities(func_addr),
        }

    # ── Context gathering ──────────────────────────────────────────────────

    def _gather_context(self, func_addr: int) -> Dict[str, Any]:
        context = {
            "disassembly": "",
            "pseudocode": "",
            "metadata": {},
            "gnn_embedding": None,
        }

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

        context["disassembly"] = "\n".join(disasm_lines)

        func_name = self._lookup_function_name(func_addr)
        calls = self._collect_calls(blocks)
        context["metadata"] = {
            "func_name": func_name,
            "func_addr": f"0x{func_addr:x}",
            "block_count": len(blocks),
            "edge_count": len(edges),
            "calls": calls,
            "dataflow_summary": self._build_dataflow_summary(blocks),
        }

        if self.pseudo is not None:
            try:
                pseudo_result = self.pseudo.decompile_function(func_addr)
                if pseudo_result and pseudo_result.get("normalized"):
                    context["pseudocode"] = pseudo_result["normalized"]
                elif pseudo_result and pseudo_result.get("pseudocode"):
                    context["pseudocode"] = pseudo_result["pseudocode"]
            except Exception:
                pass

        if self.gnn is not None:
            try:
                gnn_result = self.gnn.analyse_function(func_addr)
                context["gnn_embedding"] = gnn_result.get("graph_embedding")
            except Exception:
                pass

        return context

    def _build_dataflow_summary(self, blocks: List[int]) -> str:
        reads = set()
        writes = set()
        calls = []

        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands", [])

                if mnem in ("mov", "lea", "movzx", "movsx") and len(ops) >= 2:
                    writes.add(ops[0])
                    reads.add(ops[1])
                elif mnem in ("push",) and ops:
                    reads.add(ops[0])
                elif mnem in ("pop",) and ops:
                    writes.add(ops[0])
                elif mnem in ("call", "bl", "blr") and ops:
                    calls.append(ops[0])

        parts = []
        if writes:
            parts.append(f"Writes: {', '.join(sorted(writes)[:10])}")
        if reads:
            parts.append(f"Reads: {', '.join(sorted(reads)[:10])}")
        if calls:
            parts.append(f"Calls: {', '.join(calls[:10])}")

        return "; ".join(parts)

    # ── Classical (non-LLM) fallback methods ───────────────────────────────

    def _explain_with_llm(self, func_addr: int, level: str) -> Dict[str, Any]:
        context = self._gather_context(func_addr)

        if level == "simple":
            result = self.llm.summarize_function(**context)
            return {
                "summary": result.get("summary", "No summary available."),
                "steps": [result.get("behavior", "")],
                "variables": [],
                "vulnerabilities": [],
            }
        elif level == "deep":
            summary = self.llm.summarize_function(**context)
            vulns = self.llm.detect_vulnerabilities(
                disassembly=context.get("disassembly", ""),
                pseudocode=context.get("pseudocode", ""),
                metadata=context.get("metadata"),
            )
            types = self.llm.infer_types(**context)

            vuln_list = vulns.get("vulnerabilities", [])
            return {
                "summary": summary.get("summary", "No summary available."),
                "steps": [
                    summary.get("behavior", ""),
                    summary.get("algorithmic_intent", ""),
                    f"Complexity: {summary.get('complexity_estimate', 'unknown')}",
                ],
                "variables": types.get("locals", []),
                "vulnerabilities": vuln_list,
            }
        else:  # medium
            result = self.llm.summarize_function(**context)
            return {
                "summary": result.get("summary", "No summary available."),
                "steps": [
                    result.get("behavior", ""),
                    result.get("algorithmic_intent", ""),
                ] + result.get("side_effects", []),
                "variables": [],
                "vulnerabilities": [],
            }

    def _explain_classical(self, func_addr: int, level: str) -> Dict[str, Any]:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        block_insns = {bb: self.g.fetch_block_instructions(bb) for bb in blocks}
        calls = self._collect_calls(blocks)
        loops = self._detect_back_edges(blocks, edges)

        steps = []
        if blocks:
            steps.append(f"CFG has {len(blocks)} basic blocks and {len(edges)} edges.")
        if loops:
            steps.append(f"Contains {len(loops)} loop(s).")
        if calls:
            steps.append(f"Calls: {', '.join(calls)}.")

        summary = (
            f"{func_name} @ 0x{func_addr:x}: {len(blocks)} blocks, "
            f"{len(edges)} edges, {len(loops)} loop(s), {len(calls)} call(s)."
        )

        return {
            "summary": summary,
            "steps": steps,
            "variables": [],
            "vulnerabilities": self._classical_vulns(func_addr),
        }

    def _classical_name(self, func_addr: int) -> str:
        blocks = self.g.fetch_basic_blocks(func_addr)
        calls = self._collect_calls(blocks)
        if not calls:
            return f"sub_{func_addr:x}"
        return f"wrapper_{calls[0]}" if len(calls) == 1 else f"sub_{func_addr:x}"

    def _classical_variables(self, func_addr: int) -> List[Dict[str, str]]:
        blocks = self.g.fetch_basic_blocks(func_addr)
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
        return [{"original": r, "suggested": r, "type_hint": "register"} for r in sorted(regs)]

    def _classical_summary(self, func_addr: int) -> Dict[str, Any]:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        calls = self._collect_calls(blocks)
        return {
            "summary": f"{func_name} has {len(blocks)} block(s) and calls {', '.join(calls) if calls else 'nothing'}.",
            "behavior": "Unknown (LLM not available)",
            "side_effects": [],
            "algorithmic_intent": "Unknown",
            "complexity_estimate": "Unknown",
        }

    def _classical_vulns(self, func_addr: int) -> List[Dict[str, str]]:
        unsafe_funcs = {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}
        blocks = self.g.fetch_basic_blocks(func_addr)
        vulns = []
        for bb in blocks:
            insns = self.g.fetch_block_instructions(bb)
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands", [])
                if mnem in ("call", "bl", "blr") and ops:
                    target = str(ops[0]).lower()
                    for uf in unsafe_funcs:
                        if uf in target:
                            vulns.append({
                                "type": "unsafe_call",
                                "severity": "medium",
                                "description": f"Call to {ops[0]} may lack bounds checking.",
                                "location": f"0x{insn.get('addr', 0):x}",
                                "recommendation": f"Consider using a safer alternative to {uf}.",
                            })
        return vulns

    # ── Helpers ────────────────────────────────────────────────────────────

    def _lookup_function_name(self, func_addr: int) -> str:
        for func in self.g.fetch_functions():
            if func.get("addr") == func_addr:
                return func.get("name", f"sub_{func_addr:x}")
        return f"sub_{func_addr:x}"

    def _collect_calls(self, blocks: List[int]) -> List[str]:
        targets = set()
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
                        targets.add(name)
        return sorted(targets)

    def _detect_back_edges(self, blocks: List[int], edges: List) -> List:
        block_set = set(blocks)
        return [(s, d) for s, d in edges if s in block_set and d in block_set and d <= s]
