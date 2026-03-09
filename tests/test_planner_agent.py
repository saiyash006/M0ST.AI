"""Tests for PlannerAgent (multi-step AI orchestration)."""

import unittest
from unittest.mock import MagicMock, patch
from dataclasses import asdict

from orchestration.planner_agent import PlannerAgent, AnalysisResult


class TestAnalysisResult(unittest.TestCase):
    """Test the AnalysisResult dataclass."""

    def test_default_values(self):
        r = AnalysisResult()
        self.assertEqual(r.total_functions, 0)
        self.assertEqual(r.stages_completed, [])
        self.assertEqual(r.refined_pseudocode, {})
        self.assertEqual(r.vulnerability_hints, {})

    def test_as_dict(self):
        r = AnalysisResult(total_functions=5, stages_completed=["static"])
        d = r.to_dict()
        self.assertIn("total_functions", d)
        self.assertEqual(d["total_functions"], 5)


class TestPlannerAgentInit(unittest.TestCase):
    """Test PlannerAgent initialisation."""

    def _make_planner(self):
        return PlannerAgent(
            graph_store=MagicMock(),
            sqlite_store=MagicMock(),
            static_agent=MagicMock(),
            dynamic_agent=MagicMock(),
            graph_agent=MagicMock(),
            llm_agent=MagicMock(),
            pseudocode_agent=MagicMock(),
            semantic_agent=MagicMock(),
            verifier_agent=MagicMock(),
            z3_agent=MagicMock(),
            plugin_manager=None,
            snapshot_manager=None,
        )

    def test_init(self):
        p = self._make_planner()
        self.assertIsNotNone(p)

    def test_capabilities(self):
        cap_names = {c.name for c in PlannerAgent.CAPABILITIES}
        self.assertIn("PLANNING", cap_names)


class TestPlannerDecisions(unittest.TestCase):
    """Test decision-making methods."""

    def _make_planner(self):
        return PlannerAgent(
            graph_store=MagicMock(),
            sqlite_store=MagicMock(),
            static_agent=MagicMock(),
            dynamic_agent=MagicMock(),
            graph_agent=MagicMock(),
            llm_agent=MagicMock(),
            pseudocode_agent=MagicMock(),
            semantic_agent=MagicMock(),
            verifier_agent=MagicMock(),
            z3_agent=MagicMock(),
        )

    def test_should_run_dynamic_default(self):
        """Dynamic analysis should run when suspicious patterns exist."""
        p = self._make_planner()
        result = AnalysisResult()
        # Without evidence, default decision should be made
        decision = p._should_run_dynamic(result)
        self.assertIsInstance(decision, bool)

    def test_should_run_z3_default(self):
        """Z3 analysis decision should return a boolean."""
        p = self._make_planner()
        result = AnalysisResult()
        decision = p._should_run_z3(result)
        self.assertIsInstance(decision, bool)


class TestPlannerAICommands(unittest.TestCase):
    """Test single-function AI command methods."""

    def _make_planner(self):
        semantic = MagicMock()
        semantic.infer_function_name.return_value = {
            "name": "process_input",
            "confidence": 0.85,
        }
        semantic.summarize_function.return_value = {
            "summary": "Processes user input",
        }
        semantic.infer_types.return_value = {
            "return_type": "int",
            "parameters": [{"name": "buf", "type": "char*"}],
        }
        return PlannerAgent(
            graph_store=MagicMock(),
            sqlite_store=MagicMock(),
            static_agent=MagicMock(),
            dynamic_agent=MagicMock(),
            graph_agent=MagicMock(),
            llm_agent=MagicMock(),
            pseudocode_agent=MagicMock(),
            semantic_agent=semantic,
            verifier_agent=MagicMock(),
            z3_agent=MagicMock(),
        )

    def test_ai_name(self):
        p = self._make_planner()
        result = p.ai_name(0x1000)
        self.assertIn("name", result)
        self.assertEqual(result["name"], "process_input")

    def test_ai_explain(self):
        p = self._make_planner()
        result = p.ai_explain(0x1000)
        self.assertIn("summary", result)

    def test_ai_types(self):
        p = self._make_planner()
        result = p.ai_types(0x1000)
        self.assertIn("return_type", result)


if __name__ == "__main__":
    unittest.main()
