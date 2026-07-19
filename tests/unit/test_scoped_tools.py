"""root-scoped Agent 도구의 정상·차단 경로 테스트."""

import tempfile
import unittest
from pathlib import Path

from core.mcp_tools import create_scoped_tools
from core.path_policy import ScanPathPolicy


class ScopedToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "project"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src" / "auth.py").write_text("def login(user_input):\n    return user_input\n", encoding="utf-8")
        (self.root / "secrets.yaml").write_text("token: do-not-return\n", encoding="utf-8")
        self.tools = {tool.name: tool for tool in create_scoped_tools(ScanPathPolicy(self.root))}

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_read_source_returns_relative_grounded_lines(self) -> None:
        result = self.tools["read_source"].invoke({"file_path": "src/auth.py", "start_line": 1, "end_line": 2})
        self.assertIn("src/auth.py:1:", result)
        self.assertIn("def login", result)

    def test_read_source_rejects_absolute_and_sensitive_paths(self) -> None:
        absolute = self.tools["read_source"].invoke({
            "file_path": str(self.root / "src" / "auth.py"), "start_line": 1, "end_line": 1,
        })
        sensitive = self.tools["read_source"].invoke({
            "file_path": "secrets.yaml", "start_line": 1, "end_line": 1,
        })
        self.assertIn("상대 경로", absolute)
        self.assertIn("허용되지 않은", sensitive)
        self.assertNotIn("do-not-return", sensitive)

    def test_search_does_not_return_sensitive_file_content(self) -> None:
        result = self.tools["search_code"].invoke({"query": "do-not-return", "dir_path": "."})
        self.assertNotIn("do-not-return", result.replace("'do-not-return'", ""))
        self.assertNotIn("secrets.yaml", result)


if __name__ == "__main__":
    unittest.main()
