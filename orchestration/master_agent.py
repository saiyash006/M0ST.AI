"""
Master Agent — Backward-compatible orchestration layer.

Provides the MasterAgent class that initializes all agents and
delegates to the PlannerAgent for AI-driven analysis while
maintaining backward compatibility with the legacy CLI.
"""

import time
from datetime import datetime, timezone

from core import load_env
from core.config import get_config
from core.capabilities import Capability, enforce_capability
from storage.memory_graph_store import MemoryGraphStore
from storage.sqlite_store import SQLiteStore
from storage.snapshots import SnapshotManager
from plugins import PluginManager

# Import from new M0ST layer structure
from ai_security_agents.static_agent import StaticAgent
from ai_security_agents.heuristics_agent import HeuristicsAgent
from ai_security_agents.verifier_agent import VerifierAgent
from ai_security_agents.dynamic_agent import DynamicAgent
from ai_security_agents.semantic_agent import SemanticAgent
from ai_security_agents.graph_agent import GraphAgent
from ai_security_agents.llm_agent import LLMAgent
from ai_security_agents.pseudocode_agent import PseudocodeAgent
from ai_security_agents.llm_semantic_agent import LLMSemanticAgent
from ai_security_agents.z3_agent import Z3Agent
from orchestration.planner_agent import PlannerAgent


class MasterAgent:
    """
    Orchestration layer.

    Initializes all agents (static, dynamic, GNN, LLM, pseudocode,
    semantic, verifier, Z3) and provides both legacy pipeline
    compatibility and new AI-driven analysis via PlannerAgent.
    """

    def __init__(self):
        load_env()
        config = get_config()

        # ── Storage ────────────────────────────────────────────────────
        self.graph_store = MemoryGraphStore()
        self.sqlite_store = SQLiteStore(
            db_path=config.get("sqlite", {}).get("db_path", "storage/metadata.db")
        )
        self.snapshots = SnapshotManager(self.sqlite_store, graph_store=self.graph_store)
        self.plugins = PluginManager()

        # ── Legacy agents ──────────────────────────────────────────────
        self.static_agent = StaticAgent(self.graph_store)
        self.heuristics_agent = HeuristicsAgent(self.graph_store)
        self.verifier_agent = VerifierAgent(self.graph_store)
        self.dynamic_agent = DynamicAgent(self.graph_store)
        self.semantic_agent_legacy = SemanticAgent(self.graph_store)
        self.z3_agent = Z3Agent()

        # ── AI agents ──────────────────────────────────────────────────
        llm_provider = config.get("llm", {}).get("provider") or "none"
        llm_model = config.get("llm", {}).get("model") or None
        llm_api_key = config.get("llm", {}).get("api_key") or None
        llm_base_url = config.get("llm", {}).get("base_url") or None

        self.llm_agent = LLMAgent(
            provider=llm_provider,
            model=llm_model,
            api_key=llm_api_key,
            api_base=llm_base_url,
        )
        self.graph_agent = GraphAgent(self.graph_store)
        self.pseudocode_agent = PseudocodeAgent(self.graph_store)
        self.semantic_agent = LLMSemanticAgent(
            graph_store=self.graph_store,
            llm_agent=self.llm_agent,
            graph_agent=self.graph_agent,
            pseudocode_agent=self.pseudocode_agent,
        )

        # ── Planner ────────────────────────────────────────────────────
        self.planner = PlannerAgent(
            graph_store=self.graph_store,
            sqlite_store=self.sqlite_store,
            static_agent=self.static_agent,
            dynamic_agent=self.dynamic_agent,
            graph_agent=self.graph_agent,
            llm_agent=self.llm_agent,
            pseudocode_agent=self.pseudocode_agent,
            semantic_agent=self.semantic_agent,
            verifier_agent=self.verifier_agent,
            z3_agent=self.z3_agent,
            snapshot_manager=self.snapshots,
            plugin_manager=self.plugins,
        )

        # Register agents as LLM tools
        LLMAgent.register_tool(
            "static_analysis",
            lambda binary_path: self.static_agent.run(binary_path),
            "Run static analysis on a binary",
        )
        LLMAgent.register_tool(
            "graph_analysis",
            lambda func_addr: self.graph_agent.analyse_function(func_addr),
            "Run GNN structural analysis on a function",
        )
        LLMAgent.register_tool(
            "pseudocode",
            lambda func_addr, binary_path=None: self.pseudocode_agent.decompile_function(func_addr, binary_path),
            "Decompile a function to pseudocode",
        )

    # ── Legacy pipeline (backward compatible) ──────────────────────────

    def run_pipeline(self, binary_path: str):
        """
        Run the analysis pipeline. Uses sequential execution
        instead of the old event bus.
        """
        print("[Master] Clearing previous graph state...")
        self.graph_store.clear_graph()

        print("[Master] Launching static analysis...")
        if enforce_capability(self.static_agent, Capability.STATIC_WRITE):
            self.static_agent.run(binary_path)

        print("[Master] Running heuristics...")
        if enforce_capability(self.heuristics_agent, Capability.STATIC_READ):
            self.heuristics_agent.run()

        print("[Master] Verifying static contradictions...")
        if enforce_capability(self.verifier_agent, Capability.VERIFY):
            self.verifier_agent.verify_basicblock_edges()

        print("[Master] Running GNN analysis...")
        try:
            self.graph_agent.analyse_all_functions()
        except Exception as e:
            print(f"[Master] GNN analysis skipped: {e}")

        print("[Master] Starting dynamic tracing...")
        run_id = f"run_{int(time.time())}"
        if enforce_capability(self.dynamic_agent, Capability.DYNAMIC_EXECUTE):
            self.dynamic_agent.run(binary_path, run_id=run_id)

        print("[Master] Verifying runtime edges...")
        if enforce_capability(self.verifier_agent, Capability.VERIFY):
            self.verifier_agent.verify_basicblock_edges()

        print("[Master] Running plugins...")
        if enforce_capability(self.plugins, Capability.PLUGIN_ANALYSIS):
            self.plugins.load_plugins()
            for func in self.graph_store.fetch_functions():
                addr = func.get("addr")
                if addr is None:
                    continue
                self.plugins.run_all(self.graph_store, addr)

        print("[Master] Generating semantic explanations...")
        semantic_results = {}
        funcs = self.graph_store.fetch_functions()
        total = len(funcs)
        for i, func in enumerate(funcs, 1):
            addr = func.get("addr")
            if addr is None:
                continue
            name = func.get("name", f"sub_{addr:x}")
            print(f"  [{i}/{total}] Explaining {name} @ 0x{addr:x}...")
            try:
                semantic_results[addr] = self.semantic_agent.explain(addr)
            except Exception:
                semantic_results[addr] = self.semantic_agent_legacy.explain_function(addr)
        self.graph_store.set_semantic_summaries(semantic_results)

        print("[Master] Creating snapshot...")
        snapshot_name = f"snapshot_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        if enforce_capability(self.snapshots, Capability.SNAPSHOT):
            self.snapshots.create_snapshot(snapshot_name, description="Pipeline snapshot")

        print("[Master] Pipeline complete.")

    # ── AI-driven pipeline ─────────────────────────────────────────────

    def run_ai_pipeline(self, binary_path: str):
        """Run the full AI-driven analysis pipeline via PlannerAgent."""
        return self.planner.run_full_pipeline(binary_path)
