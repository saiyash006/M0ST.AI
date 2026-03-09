"""
Planner Agent — Multi-step orchestration and coordination.

Coordinates all agents through multi-step reasoning loops:
    static → graph → pseudocode → LLM → verify → refine
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.capabilities import Capability, enforce_capability
from core.config import get_config


@dataclass
class AnalysisResult:
    """Final output of a complete analysis pipeline."""

    binary_path: str = ""
    timestamp: str = ""

    # Per-function results
    functions: Dict[int, Dict[str, Any]] = field(default_factory=dict)

    # Aggregate analysis
    refined_pseudocode: Dict[int, str] = field(default_factory=dict)
    llm_insights: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    naming_suggestions: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    type_suggestions: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    cfg_annotations: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    vulnerability_hints: Dict[int, List[Dict]] = field(default_factory=dict)
    plugin_outputs: Dict[int, Dict[str, Any]] = field(default_factory=dict)

    # Overall stats
    stages_completed: List[str] = field(default_factory=list)
    total_functions: int = 0
    total_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "timestamp": self.timestamp,
            "total_functions": self.total_functions,
            "total_time_seconds": self.total_time_seconds,
            "stages_completed": self.stages_completed,
            "functions": {
                f"0x{addr:x}": data for addr, data in self.functions.items()
            },
            "refined_pseudocode": {
                f"0x{addr:x}": code for addr, code in self.refined_pseudocode.items()
            },
            "llm_insights": {
                f"0x{addr:x}": data for addr, data in self.llm_insights.items()
            },
            "naming_suggestions": {
                f"0x{addr:x}": data for addr, data in self.naming_suggestions.items()
            },
            "type_suggestions": {
                f"0x{addr:x}": data for addr, data in self.type_suggestions.items()
            },
            "vulnerability_hints": {
                f"0x{addr:x}": data for addr, data in self.vulnerability_hints.items()
            },
            "plugin_outputs": {
                f"0x{addr:x}": data for addr, data in self.plugin_outputs.items()
            },
        }


class PlannerAgent:
    """
    Multi-step planning and orchestration agent.

    Coordinates all other agents based on missing information,
    performs iterative refinement, and produces a final AnalysisResult.
    """

    CAPABILITIES = {Capability.PLANNING}

    def __init__(
        self,
        graph_store,
        sqlite_store=None,
        static_agent=None,
        dynamic_agent=None,
        graph_agent=None,
        llm_agent=None,
        pseudocode_agent=None,
        semantic_agent=None,
        verifier_agent=None,
        z3_agent=None,
        snapshot_manager=None,
        plugin_manager=None,
    ):
        self.g = graph_store
        self.sqlite = sqlite_store
        self.static = static_agent
        self.dynamic = dynamic_agent
        self.graph = graph_agent
        self.llm = llm_agent
        self.pseudo = pseudocode_agent
        self.semantic = semantic_agent
        self.verifier = verifier_agent
        self.z3 = z3_agent
        self.snapshots = snapshot_manager
        self.plugins = plugin_manager

        self._memory: Dict[str, Any] = {}

    # ── Full pipeline ──────────────────────────────────────────────────────

    def run_full_pipeline(self, binary_path: str) -> AnalysisResult:
        """
        Execute the complete multi-agent analysis pipeline.

        Order: static → graph → pseudocode → LLM → verify → refine → plugins
        """
        start = time.monotonic()
        result = AnalysisResult(
            binary_path=binary_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._memory = {"binary_path": binary_path, "stages": []}

        print("[Planner] Starting full analysis pipeline...")

        self._run_stage("static_analysis", result, binary_path)
        self._run_stage("gnn_analysis", result, binary_path)
        self._run_stage("pseudocode_extraction", result, binary_path)
        self._run_stage("llm_analysis", result, binary_path)
        self._run_stage("verification", result, binary_path)

        if self._should_run_dynamic(result):
            self._run_stage("dynamic_analysis", result, binary_path)

        if self._should_run_z3(result):
            self._run_stage("z3_analysis", result, binary_path)

        self._run_stage("plugin_analysis", result, binary_path)
        self._run_stage("refinement", result, binary_path)
        self._run_stage("snapshot", result, binary_path)

        result.total_functions = len(self.g.fetch_functions())
        result.total_time_seconds = time.monotonic() - start

        print(f"[Planner] Pipeline complete in {result.total_time_seconds:.1f}s. "
              f"{result.total_functions} function(s) analyzed.")

        return result

    # ── Individual stage runners ───────────────────────────────────────────

    def _run_stage(self, stage_name: str, result: AnalysisResult, binary_path: str):
        print(f"[Planner] Running stage: {stage_name}...")
        try:
            handler = getattr(self, f"_stage_{stage_name}", None)
            if handler:
                handler(result, binary_path)
                result.stages_completed.append(stage_name)
                self._memory["stages"].append(stage_name)
            else:
                print(f"[Planner] Warning: no handler for stage '{stage_name}'")
        except Exception as e:
            print(f"[Planner] Stage '{stage_name}' error: {e}")

    def _stage_static_analysis(self, result: AnalysisResult, binary_path: str):
        if self.static is None:
            print("[Planner] No static agent available. Skipping.")
            return

        self.g.clear_graph()
        self.static.run(binary_path)

        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue
            blocks = self.g.fetch_basic_blocks(addr)
            edges = self.g.fetch_flow_edges(addr)
            result.functions[addr] = {
                "name": func.get("name", f"sub_{addr:x}"),
                "addr": addr,
                "block_count": len(blocks),
                "edge_count": len(edges),
            }

    def _stage_gnn_analysis(self, result: AnalysisResult, binary_path: str):
        if self.graph is None:
            print("[Planner] No graph agent available. Skipping GNN analysis.")
            return

        embeddings = self.graph.analyse_all_functions()
        self._memory["gnn_embeddings"] = embeddings

        for addr, emb in embeddings.items():
            result.cfg_annotations[addr] = {
                "node_count": emb.get("node_count", 0),
                "edge_count": emb.get("edge_count", 0),
                "embedding_dim": len(emb.get("graph_embedding", [])),
            }

        if self.sqlite:
            try:
                for addr, emb in embeddings.items():
                    self.sqlite.save_cfg_embedding(addr, emb.get("graph_embedding", []))
            except Exception:
                pass

    def _stage_pseudocode_extraction(self, result: AnalysisResult, binary_path: str):
        if self.pseudo is None:
            print("[Planner] No pseudocode agent available. Skipping.")
            return

        pseudocode_results = self.pseudo.decompile_all(binary_path)
        self._memory["pseudocode"] = pseudocode_results

        for addr, pc in pseudocode_results.items():
            normalized = pc.get("normalized") or pc.get("pseudocode", "")
            result.refined_pseudocode[addr] = normalized

    def _stage_llm_analysis(self, result: AnalysisResult, binary_path: str):
        if self.semantic is None:
            print("[Planner] No semantic agent available. Skipping LLM analysis.")
            return

        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue

            try:
                name_result = self.semantic.infer_function_name(addr)
                result.naming_suggestions[addr] = name_result

                type_result = self.semantic.infer_types(addr)
                result.type_suggestions[addr] = type_result

                summary = self.semantic.summarize_function(addr)
                result.llm_insights[addr] = summary

                vulns = self.semantic.detect_vulnerabilities(addr)
                vuln_list = vulns.get("vulnerabilities", [])
                if vuln_list:
                    result.vulnerability_hints[addr] = vuln_list

            except Exception as e:
                print(f"[Planner] LLM analysis failed for 0x{addr:x}: {e}")

    def _stage_verification(self, result: AnalysisResult, binary_path: str):
        if self.verifier is None:
            print("[Planner] No verifier agent available. Skipping.")
            return

        try:
            self.verifier.verify_basicblock_edges()
            vr = self.g.get_verification_results()
            self._memory["verification"] = vr
        except Exception as e:
            print(f"[Planner] Verification error: {e}")

    def _stage_dynamic_analysis(self, result: AnalysisResult, binary_path: str):
        if self.dynamic is None:
            print("[Planner] No dynamic agent available. Skipping.")
            return

        import platform
        if platform.system() == "Windows":
            print("[Planner] Dynamic tracing not supported on Windows. Skipping.")
            return

        run_id = f"run_{int(time.time())}"
        self.dynamic.run(binary_path, run_id=run_id)

    def _stage_z3_analysis(self, result: AnalysisResult, binary_path: str):
        if self.z3 is None:
            print("[Planner] No Z3 agent available. Skipping.")
            return

        try:
            from analysis.constraint_pass import prune_infeasible_edges
            prune_infeasible_edges(self.g)
        except Exception as e:
            print(f"[Planner] Z3 analysis error: {e}")

    def _stage_plugin_analysis(self, result: AnalysisResult, binary_path: str):
        if self.plugins is None:
            print("[Planner] No plugin manager available. Skipping.")
            return

        try:
            self.plugins.load_plugins()
            for func in self.g.fetch_functions():
                addr = func.get("addr")
                if addr is None:
                    continue
                facts = self.plugins.run_all(self.g, addr)
                if facts:
                    result.plugin_outputs[addr] = facts
        except Exception as e:
            print(f"[Planner] Plugin analysis error: {e}")

    def _stage_refinement(self, result: AnalysisResult, binary_path: str):
        verification = self._memory.get("verification")
        if verification and isinstance(verification, dict):
            suspect_edges = verification.get("static_not_dynamic", [])
            for src, dst in suspect_edges:
                for addr, func_data in result.functions.items():
                    blocks = self.g.fetch_basic_blocks(addr)
                    if src in blocks or dst in blocks:
                        existing = result.vulnerability_hints.get(addr, [])
                        existing.append({
                            "type": "suspect_edge",
                            "severity": "low",
                            "description": f"Edge 0x{src:x}->0x{dst:x} not observed at runtime.",
                        })
                        result.vulnerability_hints[addr] = existing

        summaries = {}
        for addr, insight in result.llm_insights.items():
            if isinstance(insight, dict) and "summary" in insight:
                summaries[addr] = insight
        if summaries:
            self.g.set_semantic_summaries(summaries)

    def _stage_snapshot(self, result: AnalysisResult, binary_path: str):
        if self.snapshots is None:
            return

        try:
            snap_name = f"ai_analysis_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
            self.snapshots.create_snapshot(snap_name, description="Full pipeline")
        except Exception as e:
            print(f"[Planner] Snapshot error: {e}")

    # ── Decision helpers ───────────────────────────────────────────────────

    def _should_run_dynamic(self, result: AnalysisResult) -> bool:
        verification = self._memory.get("verification")
        if verification and isinstance(verification, dict):
            suspects = verification.get("suspect_edges", 0)
            if suspects > 0:
                return True
        return False

    def _should_run_z3(self, result: AnalysisResult) -> bool:
        for func in self.g.fetch_functions():
            addr = func.get("addr")
            if addr is None:
                continue
            edges = self.g.fetch_flow_edges(addr)
            blocks = self.g.fetch_basic_blocks(addr)
            for bb in blocks:
                out_edges = [(s, d) for s, d in edges if s == bb]
                if len(out_edges) == 2:
                    return True
        return False

    # ── Single-function analysis ───────────────────────────────────────────

    def analyse_function(self, func_addr: int, binary_path: Optional[str] = None) -> Dict[str, Any]:
        result = {}

        if self.graph:
            result["gnn"] = self.graph.analyse_function(func_addr)

        if self.pseudo:
            result["pseudocode"] = self.pseudo.decompile_function(func_addr, binary_path)

        if self.semantic:
            result["naming"] = self.semantic.infer_function_name(func_addr)
            result["types"] = self.semantic.infer_types(func_addr)
            result["summary"] = self.semantic.summarize_function(func_addr)
            result["vulnerabilities"] = self.semantic.detect_vulnerabilities(func_addr)

        return result

    def ai_name(self, func_addr: int) -> Dict[str, Any]:
        if self.semantic:
            return self.semantic.infer_function_name(func_addr)
        return {"error": "Semantic agent not available"}

    def ai_explain(self, func_addr: int) -> Dict[str, Any]:
        if self.semantic:
            return self.semantic.summarize_function(func_addr)
        return {"error": "Semantic agent not available"}

    def ai_types(self, func_addr: int) -> Dict[str, Any]:
        if self.semantic:
            return self.semantic.infer_types(func_addr)
        return {"error": "Semantic agent not available"}

    def ai_refine(self, func_addr: int, binary_path: Optional[str] = None) -> Dict[str, Any]:
        return self.analyse_function(func_addr, binary_path)
