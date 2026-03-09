"""Tests for LLMAgent (LLM wrapper for RE inference)."""

import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from ai_security_agents.llm_agent import LLMAgent


class TestLLMAgentInit(unittest.TestCase):
    """Test LLMAgent initialisation."""

    def test_init_no_provider(self):
        """Agent initialises with provider=none (disabled)."""
        agent = LLMAgent(provider="none")
        self.assertIsNotNone(agent)
        self.assertIsNone(agent.client)

    def test_init_default(self):
        """Agent initialises with default config when no env vars are set."""
        agent = LLMAgent()
        self.assertIsNotNone(agent)

    def test_capabilities(self):
        cap_names = {c.name for c in LLMAgent.CAPABILITIES}
        self.assertIn("LLM_INFERENCE", cap_names)
        self.assertIn("SEMANTIC_REASON", cap_names)


class TestLLMAgentPromptBuilding(unittest.TestCase):
    """Test prompt construction logic."""

    def setUp(self):
        self.agent = LLMAgent(provider="none")

    def test_build_prompt_minimal(self):
        """Prompt builds with minimal context."""
        prompt = self.agent._build_prompt(
            task="name",
            instruction="Suggest a function name.",
            disassembly="push rbp\nmov rbp, rsp\nret",
        )
        self.assertIn("[DISASSEMBLY]", prompt)
        self.assertIn("push rbp", prompt)

    def test_build_prompt_full_context(self):
        """Prompt builds with all optional context."""
        prompt = self.agent._build_prompt(
            task="explain",
            instruction="Explain the function.",
            disassembly="push rbp",
            pseudocode="int main() { return 0; }",
            gnn_embedding=[0.1, 0.2, 0.3],
            metadata={"imports": ["printf"], "strings": ["hello"]},
        )
        self.assertIn("[PSEUDOCODE]", prompt)
        self.assertIn("[CFG_EMBEDDING]", prompt)
        self.assertIn("[METADATA]", prompt)
        self.assertIn("printf", prompt)

    def test_build_prompt_includes_task(self):
        """Prompt includes the task description."""
        prompt = self.agent._build_prompt(
            task="types",
            instruction="Infer types.",
            disassembly="xor eax, eax",
        )
        self.assertIn("types", prompt.lower())


class TestLLMAgentToolRegistry(unittest.TestCase):
    """Test tool-calling support."""

    def setUp(self):
        # Clear any previously registered tools
        LLMAgent.TOOL_REGISTRY = {}

    def test_register_and_resolve_tool(self):
        """Register a tool and resolve a call to it."""

        def my_tool(addr: int) -> str:
            return f"result_{addr}"

        LLMAgent.register_tool("my_tool", my_tool, "Test tool")
        agent = LLMAgent(provider="none")
        result = agent.resolve_tool_call("my_tool", {"addr": 42})
        self.assertEqual(result, "result_42")

    def test_resolve_unknown_tool(self):
        """Resolving an unknown tool returns an error dict."""
        agent = LLMAgent(provider="none")
        result = agent.resolve_tool_call("nonexistent", {})
        self.assertIn("error", result)


class TestLLMAgentDisabled(unittest.TestCase):
    """Test that disabled agent returns graceful fallbacks."""

    def setUp(self):
        self.agent = LLMAgent(provider="none")

    def test_infer_name_disabled(self):
        result = self.agent.infer_function_name("push rbp\nret")
        self.assertIsInstance(result, dict)

    def test_summarize_disabled(self):
        result = self.agent.summarize_function("push rbp\nret")
        self.assertIsInstance(result, dict)

    def test_detect_vulns_disabled(self):
        result = self.agent.detect_vulnerabilities("push rbp\nret")
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
