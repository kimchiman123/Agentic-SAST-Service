"""공용 파이프라인 서비스의 외부 의존성 없는 단위 테스트."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import pipeline


class FakeScanner:
    def __init__(self, _policy):
        pass

    def run_scan(self, _target):
        return {}


class FakeContextExtractor:
    def __init__(self, _policy):
        pass

    def extract_contexts(self, _results, _target):
        return []

    def extract_critical_files(self, _target):
        return []


class FakeKnowledgeBase:
    def ensure_ready(self):
        return None


def fake_pdf(_content, path):
    Path(path).write_bytes(b"pdf")
    return path


def fake_xlsx(_findings, path):
    Path(path).write_bytes(b"xlsx")
    return path


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        pipeline._KNOWLEDGE_BASE = None

    def test_empty_scan_returns_run_scoped_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as target_dir, tempfile.TemporaryDirectory() as output_dir:
            events = []
            with (
                patch.object(pipeline, "SemgrepRunner", FakeScanner),
                patch.object(pipeline, "ContextExtractor", FakeContextExtractor),
                patch.object(pipeline, "ISMSKnowledgeBase", FakeKnowledgeBase),
                patch.object(pipeline, "scan_dependencies", return_value=[]),
                patch.object(pipeline, "format_report", return_value="# report"),
                patch.object(pipeline, "export_pdf", side_effect=fake_pdf),
                patch.object(pipeline, "export_xlsx", side_effect=fake_xlsx),
            ):
                result = pipeline.run_pipeline(
                    target_dir,
                    output_root=Path(output_dir),
                    progress_callback=lambda phase, _message, value: events.append((phase, value)),
                )

            self.assertEqual(result.findings, [])
            self.assertTrue(Path(result.artifacts.json).is_file())
            self.assertEqual(Path(result.artifacts.json).parent.name, result.run_id)
            self.assertEqual(events[-1], ("complete", 1.0))

    def test_empty_semgrep_scan_still_collects_critical_contexts(self) -> None:
        class CriticalContextExtractor(FakeContextExtractor):
            def extract_critical_files(self, _target):
                return [{"file_path": "auth.py", "content": "check_permission()"}]

        captured = {}

        class FakeAgent:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.budget = type("Budget", (), {"stop_reason": staticmethod(lambda: "")})()

            @staticmethod
            def analyze_critical_logic(_contexts):
                return []

        with tempfile.TemporaryDirectory() as target_dir, tempfile.TemporaryDirectory() as output_dir:
            with (
                patch.object(pipeline, "SemgrepRunner", FakeScanner),
                patch.object(pipeline, "ContextExtractor", CriticalContextExtractor),
                patch.object(pipeline, "ISMSKnowledgeBase", FakeKnowledgeBase),
                patch.object(pipeline, "OpenAIAgent", FakeAgent),
                patch.object(pipeline, "scan_dependencies", return_value=[]),
                patch.object(pipeline, "format_report", return_value="# report"),
                patch.object(pipeline, "export_pdf", side_effect=fake_pdf),
                patch.object(pipeline, "export_xlsx", side_effect=fake_xlsx),
            ):
                pipeline.run_pipeline(target_dir, output_root=Path(output_dir), api_key="nvapi-" + "c" * 32)

        self.assertTrue(captured["api_key"].startswith("nvapi-"))

    def test_invalid_target_does_not_leave_scan_locked(self) -> None:
        with self.assertRaises(ValueError):
            pipeline.run_pipeline("path-that-does-not-exist")
        self.assertTrue(pipeline._SCAN_LOCK.acquire(blocking=False))
        pipeline._SCAN_LOCK.release()

    def test_rejects_second_in_process_scan(self) -> None:
        self.assertTrue(pipeline._SCAN_LOCK.acquire(blocking=False))
        try:
            with self.assertRaises(pipeline.PipelineBusyError):
                pipeline.run_pipeline("unused-while-locked")
        finally:
            pipeline._SCAN_LOCK.release()

    def test_explicit_api_key_is_passed_without_environment_mutation(self) -> None:
        captured = {}

        class CandidateScanner(FakeScanner):
            def run_scan(self, _target):
                return {"results": [{"check_id": "test"}]}

        class CriticalContextExtractor(FakeContextExtractor):
            def extract_critical_files(self, _target):
                return [{"file_path": "app.py", "content": "dangerous_call()"}]

        class FakeBudget:
            @staticmethod
            def stop_reason():
                return ""

        class FakeAgent:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.budget = FakeBudget()

            @staticmethod
            def analyze_critical_logic(_contexts):
                return []

        api_key = "sk-" + "b" * 32
        with tempfile.TemporaryDirectory() as target_dir, tempfile.TemporaryDirectory() as output_dir:
            with (
                patch.object(pipeline, "SemgrepRunner", CandidateScanner),
                patch.object(pipeline, "ContextExtractor", CriticalContextExtractor),
                patch.object(pipeline, "ISMSKnowledgeBase", FakeKnowledgeBase),
                patch.object(pipeline, "OpenAIAgent", FakeAgent),
                patch.object(pipeline, "scan_dependencies", return_value=[]),
                patch.object(pipeline, "format_report", return_value="# report"),
                patch.object(pipeline, "export_pdf", side_effect=fake_pdf),
                patch.object(pipeline, "export_xlsx", side_effect=fake_xlsx),
                patch.dict("os.environ", {}, clear=True),
            ):
                pipeline.run_pipeline(target_dir, output_root=Path(output_dir), api_key=api_key)
                self.assertNotIn("OPENAI_API_KEY", os.environ)

        self.assertEqual(captured["api_key"], api_key)


if __name__ == "__main__":
    unittest.main()
