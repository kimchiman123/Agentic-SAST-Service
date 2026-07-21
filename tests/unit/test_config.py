"""API 키의 세션 적용 및 선택적 `.env` 저장 테스트."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import config


VALID_KEY = "sk-" + "a" * 32
VALID_NVIDIA_KEY = "nvapi-" + "b" * 32


class ConfigTests(unittest.TestCase):
    def test_runtime_settings_uses_defaults_and_provider_specific_key(self) -> None:
        settings = config.RuntimeSettings.from_env({"NVIDIA_API_KEY": VALID_NVIDIA_KEY})
        self.assertEqual(settings.provider, "nvidia")
        self.assertEqual(settings.batch.max_items, 8)
        self.assertEqual(settings.upload.max_files, 500)

    def test_runtime_settings_accepts_legacy_nvidia_typo_without_environment_mutation(self) -> None:
        settings = config.RuntimeSettings.from_env({"NVDIA_API_KEY": VALID_NVIDIA_KEY})
        self.assertEqual(settings.provider, "nvidia")
        self.assertEqual(settings.api_key, VALID_NVIDIA_KEY)

    def test_runtime_settings_rejects_invalid_integer_instead_of_falling_back(self) -> None:
        with self.assertRaises(config.ConfigError) as raised:
            config.RuntimeSettings.from_env({"SAST_BATCH_MAX_ITEMS": "many"})
        self.assertIn("SAST_BATCH_MAX_ITEMS", str(raised.exception))

    def test_runtime_settings_rejects_batch_larger_than_context_window(self) -> None:
        with self.assertRaises(config.ConfigError):
            config.RuntimeSettings.from_env({"NVIDIA_CONTEXT_WINDOW_TOKENS": "8192"})

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

    def test_nvidia_key_is_accepted_by_generic_validator_only(self) -> None:
        self.assertEqual(config.validate_llm_api_key(VALID_NVIDIA_KEY), VALID_NVIDIA_KEY)
        with self.assertRaises(config.ConfigError):
            config.validate_openai_api_key(VALID_NVIDIA_KEY)

    def test_nvidia_key_persists_under_provider_specific_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / ".env"
            env_file.write_text("OTHER=value\n", encoding="utf-8")
            with patch.object(config, "PROJECT_ROOT", root), patch.object(config, "PROJECT_ENV_FILE", env_file):
                config.configure_llm_api_key(VALID_NVIDIA_KEY, persist=True)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("NVIDIA_API_KEY", content)
            self.assertIn(VALID_NVIDIA_KEY, content)
            self.assertNotIn("OPENAI_API_KEY", content)

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
