"""Tests for GraphAgent (GNN-based structural analysis)."""

import unittest
from unittest.mock import MagicMock, patch

from ai_security_agents.graph_agent import GraphAgent
from storage.memory_graph_store import MemoryGraphStore


class TestGraphAgent(unittest.TestCase):
    """Unit tests for GraphAgent."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        # Insert a simple function with two blocks
        self.graph.create_function("test_func", 0x1000)
        self.graph.create_basic_block(0x1000, 0x1000)
        self.graph.create_basic_block(0x1000, 0x1010)
        self.graph.add_flow_edge(0x1000, 0x1010)
        # Add some instructions
        self.graph.create_instruction(0x1000, 0x1000, "push", ["rbp"])
        self.graph.create_instruction(0x1000, 0x1004, "mov", ["rbp", "rsp"])
        self.graph.create_instruction(0x1010, 0x1010, "pop", ["rbp"])
        self.graph.create_instruction(0x1010, 0x1014, "ret", [])

        self.agent = GraphAgent(self.graph, model_path=None)

    def test_init(self):
        """Agent initialises without errors."""
        self.assertIsNotNone(self.agent)

    def test_capabilities(self):
        """Agent declares expected capabilities."""
        cap_names = {c.name for c in GraphAgent.CAPABILITIES}
        self.assertIn("GNN_INFERENCE", cap_names)
        self.assertIn("STATIC_READ", cap_names)

    def test_analyse_function_returns_dict(self):
        """analyse_function returns a dict with expected keys."""
        result = self.agent.analyse_function(0x1000)
        self.assertIsInstance(result, dict)
        self.assertIn("func_addr", result)
        self.assertIn("node_count", result)
        self.assertIn("edge_count", result)
        self.assertEqual(result["func_addr"], 0x1000)
        self.assertEqual(result["node_count"], 2)

    def test_analyse_function_unknown_addr(self):
        """analyse_function handles missing function gracefully."""
        result = self.agent.analyse_function(0xDEAD)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["edge_count"], 0)

    def test_analyse_all_functions(self):
        """analyse_all_functions covers every function in the graph."""
        results = self.agent.analyse_all_functions()
        self.assertIsInstance(results, dict)
        self.assertIn(0x1000, results)

    def test_get_graph_embedding_for_llm(self):
        """get_graph_embedding_for_llm returns a JSON string of floats."""
        emb = self.agent.get_graph_embedding_for_llm(0x1000)
        self.assertIsInstance(emb, str)
        import json
        parsed = json.loads(emb)
        self.assertIsInstance(parsed, list)
        self.assertTrue(all(isinstance(x, (int, float)) for x in parsed))

    def test_get_graph_embedding_b64(self):
        """get_graph_embedding_b64 returns a base64 string."""
        b64 = self.agent.get_graph_embedding_b64(0x1000)
        self.assertIsInstance(b64, str)
        self.assertTrue(len(b64) > 0)

    def test_fallback_embedding_consistency(self):
        """Fallback embeddings for the same function are deterministic."""
        e1 = self.agent.get_graph_embedding_for_llm(0x1000)
        e2 = self.agent.get_graph_embedding_for_llm(0x1000)
        self.assertEqual(e1, e2)


class TestGraphAgentEmptyGraph(unittest.TestCase):
    """Edge-case tests with an empty graph."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        self.agent = GraphAgent(self.graph, model_path=None)

    def test_analyse_all_empty(self):
        results = self.agent.analyse_all_functions()
        self.assertEqual(results, {})


if __name__ == "__main__":
    unittest.main()
