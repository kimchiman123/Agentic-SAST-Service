"""Agent 계획·검증·예산 제어의 외부 API 없는 단위 테스트."""

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from langchain_core.messages import AIMessage

from core.agent import AnalysisLimits, FindingModel, OpenAIAgent, OutputModel, ScanBudget
from core.path_policy import ScanPathPolicy


class ScanBudgetTests(unittest.TestCase):
    def test_enforces_global_context_tool_llm_and_finding_limits(self) -> None:
        budget = ScanBudget(
            AnalysisLimits(max_contexts=2, max_tool_calls=3, max_llm_calls=2, max_findings=2)
        )
        self.assertEqual(budget.consume_contexts(5), 2)
        self.assertEqual(budget.consume_contexts(1), 0)
        self.assertTrue(budget.consume_llm())
        self.assertTrue(budget.consume_llm())
        self.assertFalse(budget.consume_llm())
        self.assertEqual(budget.consume_tools(2), 2)
        self.assertEqual(budget.consume_tools(2), 1)
        self.assertEqual(budget.consume_findings(3), 2)


class WorkflowRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("dangerous_call(user_input)\n", encoding="utf-8")
        self.agent = OpenAIAgent.__new__(OpenAIAgent)
        self.agent.limits = AnalysisLimits(max_llm_calls=0)
        self.agent.budget = ScanBudget(self.agent.limits)
        self.agent.path_policy = ScanPathPolicy(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_tool_round_limit_forces_report(self) -> None:
        state = {
            "messages": [AIMessage(content="", tool_calls=[{"name": "read_source", "args": {}, "id": "1", "type": "tool_call"}])],
            "tool_rounds": 3,
            "max_tool_rounds": 3,
        }
        self.assertEqual(self.agent._should_continue_tools(state), "final_report")

    def test_verifier_rejects_high_finding_without_location_and_evidence(self) -> None:
        state = {
            "candidate_findings": [{"severity": "HIGH", "title": "unsupported"}],
            "revision_count": 1,
        }
        result = self.agent._verify_node(state)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["verification"]["revision_required"])
        self.assertEqual(self.agent._should_revise({**state, **result}), "end")

    def test_verifier_keeps_grounded_low_finding_without_llm_budget(self) -> None:
        state = {
            "candidate_findings": [{
                "severity": "LOW",
                "title": "grounded",
                "file_path": "src/app.py",
                "affected_code": "dangerous_call(user_input)",
            }]
        }
        result = self.agent._verify_node(state)
        self.assertEqual(len(result["findings"]), 1)

    def test_verifier_rejects_fabricated_code_for_real_file(self) -> None:
        state = {
            "candidate_findings": [{
                "severity": "HIGH",
                "title": "fabricated",
                "file_path": "src/app.py",
                "affected_code": "not_in_the_file()",
            }],
            "revision_count": 1,
        }
        result = self.agent._verify_node(state)
        self.assertEqual(result["findings"], [])

    def test_verifier_normalizes_fence_language_and_line_prefix(self) -> None:
        state = {
            "candidate_findings": [{
                "severity": "HIGH",
                "title": "fenced evidence",
                "file_path": "src/app.py",
                "affected_code": "```python\n20: dangerous_call(user_input)\n```",
            }]
        }
        result = self.agent._verify_node(state)
        self.assertEqual(len(result["findings"]), 1)

    def test_verifier_accepts_summary_only_with_server_line_evidence(self) -> None:
        evidence = self.agent._evidence_from_context({
            "file_path": "src/app.py",
            "start_line": 1,
            "end_line": 1,
        })
        state = {
            "candidate_findings": [{
                "severity": "HIGH",
                "title": "summary evidence",
                "file_path": "src/app.py",
                "affected_code": "if (...) { ... }",
                "_evidence": evidence,
            }]
        }
        result = self.agent._verify_node(state)
        self.assertEqual(len(result["findings"]), 1)

        state["candidate_findings"][0]["_evidence"]["snippet"] = "tampered"
        self.assertEqual(self.agent._verify_node(state)["findings"], [])

    def test_revision_keeps_evidence_separate_for_same_file(self) -> None:
        second_line = "another_dangerous_call(user_input)"
        (self.root / "src" / "app.py").write_text(
            f"dangerous_call(user_input)\n{second_line}\n", encoding="utf-8"
        )
        originals = [
            {
                "file_path": "src/app.py",
                "affected_code": "dangerous_call(user_input)",
                "is_true_positive": False,
                "vulnerability_type": "Code Injection",
                "title": "first",
            },
            {
                "file_path": "src/app.py",
                "affected_code": second_line,
                "is_true_positive": True,
                "vulnerability_type": "Logic Bypass",
                "title": "second",
            },
        ]

        class StubStructuredLlm:
            @staticmethod
            def invoke(_messages):
                return OutputModel(findings=[
                    FindingModel(
                        file_path="src/app.py",
                        affected_code="dangerous_call(user_input)",
                        title="revised first",
                    ),
                    FindingModel(
                        file_path="src/app.py",
                        affected_code=second_line,
                        title="revised second",
                    ),
                ])

        self.agent.structured_llm = StubStructuredLlm()
        self.agent.limits = AnalysisLimits(max_llm_calls=1)
        self.agent.budget = ScanBudget(self.agent.limits)
        result = self.agent._revise_node({"candidate_findings": originals, "verification": {}})

        self.assertEqual([item["affected_code"] for item in result["candidate_findings"]], [
            "dangerous_call(user_input)", second_line,
        ])
        self.assertFalse(result["candidate_findings"][0]["is_true_positive"])
        self.assertEqual(result["candidate_findings"][1]["vulnerability_type"], "Logic Bypass")

    def test_deep_finding_line_range_creates_server_evidence(self) -> None:
        class StubStructuredLlm:
            @staticmethod
            def invoke(_messages):
                return OutputModel(findings=[FindingModel(
                    file_path="src/app.py",
                    affected_code="dangerous_call(...)",
                    evidence_start_line=1,
                    evidence_end_line=1,
                    title="deep finding",
                )])

        self.agent.structured_llm = StubStructuredLlm()
        self.agent.isms_kb = None
        self.agent.osv_vulns = []
        self.agent.limits = AnalysisLimits(max_llm_calls=1)
        self.agent.budget = ScanBudget(self.agent.limits)
        result = self.agent._final_report_node({
            "messages": [],
            "context": {"file_path": "src/app.py", "content": "dangerous_call(user_input)\n"},
            "context_type": "deep_analysis",
            "analysis_plan": {},
        })

        candidate = result["candidate_findings"][0]
        self.assertEqual(candidate["_evidence"]["path"], "src/app.py")
        self.assertEqual(len(self.agent._verify_node(result)["findings"]), 1)

    def test_revision_failure_keeps_approved_internal_evidence(self) -> None:
        evidence = self.agent._evidence_from_context({
            "file_path": "src/app.py", "start_line": 1, "end_line": 1,
        })
        candidates = [
            {
                "file_path": "src/app.py",
                "affected_code": "dangerous_call(...)",
                "_evidence": evidence,
                "title": "approved",
            },
            {
                "file_path": "src/app.py",
                "affected_code": "fabricated(...)",
                "title": "rejected",
            },
        ]

        class FailingStructuredLlm:
            @staticmethod
            def invoke(_messages):
                raise RuntimeError("expected test failure")

        self.agent.structured_llm = FailingStructuredLlm()
        self.agent.limits = AnalysisLimits(max_llm_calls=1)
        self.agent.budget = ScanBudget(self.agent.limits)
        revised = self.agent._revise_node({
            "candidate_findings": candidates,
            "verification": {"approved_indices": [0], "revision_required": True},
            "findings": [{"file_path": "src/app.py", "affected_code": "dangerous_call(...)"}],
        })

        self.assertEqual(len(revised["candidate_findings"]), 1)
        self.assertIn("_evidence", revised["candidate_findings"][0])
        self.assertEqual(len(self.agent._verify_node(revised)["findings"]), 1)

    def test_graph_compiles_with_root_scoped_tools(self) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-not-a-real-key"}):
            agent = OpenAIAgent(target_root=str(self.root))
        self.assertEqual(type(agent.graph).__name__, "CompiledStateGraph")


if __name__ == "__main__":
    unittest.main()
