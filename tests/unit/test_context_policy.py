"""ContextExtractor가 공통 파일 경계 정책을 우회하지 않는지 검사."""

import tempfile
import unittest
from pathlib import Path

from core.context_builder import ContextExtractor
from core.path_policy import ScanPathPolicy


class ContextPolicyTests(unittest.TestCase):
    def test_critical_file_collection_excludes_secrets_and_generated_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "auth.py").write_text("def login(): pass\n", encoding="utf-8")
            (root / ".env").write_text("OPENAI_API_KEY=secret\n", encoding="utf-8")
            (root / "reports").mkdir()
            (root / "reports" / "auth.py").write_text("secret\n", encoding="utf-8")

            extractor = ContextExtractor(ScanPathPolicy(root))
            files = extractor.extract_critical_files(str(root))

            self.assertEqual([item["file_path"] for item in files], ["src/auth.py"])
            self.assertNotIn("secret", files[0]["content"])

    def test_semgrep_external_path_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "project"
            root.mkdir()
            outside = Path(temp_dir) / "outside.py"
            outside.write_text("secret\n", encoding="utf-8")
            scan = {
                "results": [{
                    "path": str(outside),
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {},
                }]
            }
            extractor = ContextExtractor(ScanPathPolicy(root))
            self.assertEqual(extractor.extract_contexts(scan, str(root)), [])


if __name__ == "__main__":
    unittest.main()
