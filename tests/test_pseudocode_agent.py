"""Tests for PseudocodeAgent (decompilation + normalization)."""

import unittest
from unittest.mock import MagicMock, patch

from ai_security_agents.pseudocode_agent import PseudocodeAgent
from storage.memory_graph_store import MemoryGraphStore


class TestPseudocodeAgent(unittest.TestCase):
    """Unit tests for PseudocodeAgent."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        # Add a minimal function
        self.graph.create_function("test_func", 0x1000)
        self.graph.create_basic_block(0x1000, 0x1000)
        self.graph.create_instruction(0x1000, 0x1000, "push", ["rbp"])
        self.graph.create_instruction(0x1000, 0x1004, "mov", ["rbp", "rsp"])
        self.graph.create_instruction(0x1000, 0x1008, "xor", ["eax", "eax"])
        self.graph.create_instruction(0x1000, 0x100C, "pop", ["rbp"])
        self.graph.create_instruction(0x1000, 0x1010, "ret", [])

        self.agent = PseudocodeAgent(self.graph)

    def test_init(self):
        self.assertIsNotNone(self.agent)

    def test_capabilities(self):
        cap_names = {c.name for c in PseudocodeAgent.CAPABILITIES}
        self.assertIn("PSEUDOCODE", cap_names)
        self.assertIn("STATIC_READ", cap_names)

    def test_normalize_pseudocode(self):
        """Normalization cleans extraneous whitespace."""
        raw = "   int   main ( ) {\n\n\n    return  0 ;\n}\n\n"
        cleaned = self.agent._normalize_pseudocode(raw)
        # Should strip trailing whitespace and collapse blank lines
        self.assertNotIn("\n\n\n", cleaned)

    def test_normalize_preserves_structure(self):
        """Normalization preserves curly braces and semicolons."""
        raw = "int main() {\n    if (x > 0) {\n        return 1;\n    }\n    return 0;\n}"
        cleaned = self.agent._normalize_pseudocode(raw)
        self.assertIn("{", cleaned)
        self.assertIn("}", cleaned)
        self.assertIn("return", cleaned)

    def test_decompile_function_fallback(self):
        """Without Ghidra/r2, decompile_function should still return a result."""
        result = self.agent.decompile_function(0x1000)
        self.assertIsInstance(result, dict)
        # Should have at least pseudocode or error key
        self.assertTrue("pseudocode" in result or "error" in result)

    def test_extract_metadata(self):
        """Variable and call extraction from pseudocode."""
        code = """
int process_data(char *buf, int len) {
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = buf[i] ^ 0x41;
    }
    printf("done\\n");
    return 0;
}
"""
        calls = self.agent._extract_calls(code)
        self.assertIsInstance(calls, list)
        self.assertIn("printf", calls)

        variables = self.agent._extract_variables(code)
        self.assertIsInstance(variables, list)

        has_loops = self.agent._detect_loops(code)
        self.assertTrue(has_loops)


class TestPseudocodeAgentNoBinary(unittest.TestCase):
    """Tests when no binary is loaded."""

    def setUp(self):
        self.graph = MemoryGraphStore()
        self.agent = PseudocodeAgent(self.graph)

    def test_decompile_no_function(self):
        """Decompiling a non-existent function returns error."""
        result = self.agent.decompile_function(0xDEAD)
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
