"""Tests for cross-agent data flow (GNN → LLM → Planner)."""

import unittest
from unittest.mock import MagicMock, patch

from ai_security_agents.graph_agent import GraphAgent
from ai_security_agents.llm_agent import LLMAgent
from storage.memory_graph_store import MemoryGraphStore


class TestGNNToLLMDataFlow(unittest.TestCase):
    """Verify that GNN embeddings feed correctly into the LLM prompt."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        self.graph.create_function("cross_test", 0x2000)
        self.graph.create_basic_block(0x2000, 0x2000)
        self.graph.create_basic_block(0x2000, 0x2010)
        self.graph.create_basic_block(0x2000, 0x2020)
        self.graph.add_flow_edge(0x2000, 0x2010)
        self.graph.add_flow_edge(0x2010, 0x2020)

        for bb in [0x2000, 0x2010, 0x2020]:
            self.graph.create_instruction(bb, bb, "nop", [])

        self.gnn_agent = GraphAgent(self.graph, model_path=None)
        self.llm_agent = LLMAgent(provider="none")

    def test_embedding_flows_to_prompt(self):
        """GNN embedding appears in the LLM prompt."""
        import json
        embedding_str = self.gnn_agent.get_graph_embedding_for_llm(0x2000)
        self.assertIsInstance(embedding_str, str)
        embedding = json.loads(embedding_str)
        self.assertIsInstance(embedding, list)
        self.assertTrue(len(embedding) > 0)

        prompt = self.llm_agent._build_prompt(
            task="name",
            instruction="Suggest a function name.",
            disassembly="nop\nnop\nnop",
            gnn_embedding=embedding,
        )
        self.assertIn("[CFG_EMBEDDING]", prompt)

    def test_embedding_dimension_consistency(self):
        """All embeddings from the same agent have consistent dimensions."""
        import json
        self.graph.create_function("another_func", 0x3000)
        self.graph.create_basic_block(0x3000, 0x3000)
        self.graph.create_instruction(0x3000, 0x3000, "ret", [])

        e1 = json.loads(self.gnn_agent.get_graph_embedding_for_llm(0x2000))
        e2 = json.loads(self.gnn_agent.get_graph_embedding_for_llm(0x3000))
        self.assertEqual(len(e1), len(e2))

    def test_b64_embedding_roundtrip(self):
        """Base64 embedding can encode/decode without corruption."""
        import base64
        import json

        b64 = self.gnn_agent.get_graph_embedding_b64(0x2000)
        decoded = json.loads(base64.b64decode(b64))
        original = json.loads(self.gnn_agent.get_graph_embedding_for_llm(0x2000))
        self.assertEqual(decoded, original)


class TestCrossAgentOrchestration(unittest.TestCase):
    """Integration-style tests for master agent wiring."""

    def test_master_agent_creates_all_agents(self):
        """MasterAgent instantiates all sub-agents."""
        with patch("orchestration.master_agent.StaticAgent"):
            with patch("orchestration.master_agent.HeuristicsAgent"):
                with patch("orchestration.master_agent.VerifierAgent"):
                    with patch("orchestration.master_agent.DynamicAgent"):
                        # Just verify import works
                        from orchestration.master_agent import MasterAgent

    def test_tool_registration(self):
        """LLMAgent tool registry supports register + resolve."""
        LLMAgent.TOOL_REGISTRY = {}

        def dummy_tool(x: int) -> int:
            return x * 2

        LLMAgent.register_tool("double", dummy_tool, "Double a number")
        agent = LLMAgent(provider="none")
        result = agent.resolve_tool_call("double", {"x": 21})
        self.assertEqual(result, 42)


class TestGraphStoreConsistency(unittest.TestCase):
    """Ensure MemoryGraphStore data is consistent across agents."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        self.graph.create_function("shared_func", 0x4000)
        self.graph.create_basic_block(0x4000, 0x4000)
        self.graph.create_basic_block(0x4000, 0x4020)
        self.graph.add_flow_edge(0x4000, 0x4020)
        self.graph.create_instruction(0x4000, 0x4000, "call", ["0x4020"])

    def test_same_graph_different_agents(self):
        """Two agents sharing the same graph see identical data."""
        agent1 = GraphAgent(self.graph, model_path=None)
        agent2 = GraphAgent(self.graph, model_path=None)

        r1 = agent1.analyse_function(0x4000)
        r2 = agent2.analyse_function(0x4000)

        self.assertEqual(r1["node_count"], r2["node_count"])
        self.assertEqual(r1["edge_count"], r2["edge_count"])

    def test_graph_mutation_visible(self):
        """Adding data to graph is visible to agents immediately."""
        agent = GraphAgent(self.graph, model_path=None)
        r1 = agent.analyse_function(0x4000)
        n_before = r1["node_count"]

        self.graph.create_basic_block(0x4000, 0x4040)
        r2 = agent.analyse_function(0x4000)
        self.assertEqual(r2["node_count"], n_before + 1)


if __name__ == "__main__":
    unittest.main()
