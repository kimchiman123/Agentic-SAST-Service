"""API 키의 세션 적용 및 선택적 `.env` 저장 테스트."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import config


VALID_KEY = "sk-" + "a" * 32


class ConfigTests(unittest.TestCase):
    def test_env_temp_files_are_ignored(self) -> None:
        gitignore = Path(__file__).resolve().parents[2] / ".gitignore"
        self.assertIn(".env.*.tmp", gitignore.read_text(encoding="utf-8"))

    def test_session_key_is_returned_without_environment_mutation(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(config.configure_openai_api_key(VALID_KEY), VALID_KEY)
            self.assertNotIn("OPENAI_API_KEY", os.environ)

    def test_rejects_injection_and_invalid_characters(self) -> None:
        for value in ("", " sk-" + "a" * 32, VALID_KEY + "\nINJECT=1", "sk-abc$def" + "a" * 20):
            with self.subTest(value_length=len(value)), self.assertRaises(config.ConfigError):
                config.validate_openai_api_key(value)

    def test_persist_preserves_other_values_and_replaces_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / ".env"
            env_file.write_text("OTHER=value\nOPENAI_API_KEY='old'\n", encoding="utf-8")
            with patch.object(config, "PROJECT_ROOT", root), patch.object(config, "PROJECT_ENV_FILE", env_file):
                config.configure_openai_api_key(VALID_KEY, persist=True)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("OTHER=value", content)
            self.assertIn(VALID_KEY, content)
            self.assertNotIn("old", content)
            self.assertEqual(list(root.glob(".env.*.tmp")), [])

    def test_rejects_symlink_env_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.write_text("safe\n", encoding="utf-8")
            env_file = root / ".env"
            try:
                env_file.symlink_to(outside)
            except (NotImplementedError, OSError):
                self.skipTest("symlink 생성 권한이 없습니다.")
            with patch.object(config, "PROJECT_ROOT", root), patch.object(config, "PROJECT_ENV_FILE", env_file):
                with self.assertRaises(config.ConfigError):
                    config.configure_openai_api_key(VALID_KEY, persist=True)
            self.assertEqual(outside.read_text(encoding="utf-8"), "safe\n")


if __name__ == "__main__":
    unittest.main()
