"""ScanPathPolicy 단위 테스트."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from core.path_policy import PathPolicyError, ScanPathPolicy


class ScanPathPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "project"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
        self.policy = ScanPathPolicy(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_accepts_regular_file_and_directory(self) -> None:
        self.assertEqual(self.policy.validate_file("src/app.py"), (self.root / "src/app.py").resolve())
        self.assertEqual(self.policy.validate_directory("src"), (self.root / "src").resolve())
        self.assertEqual(self.policy.safe_relative_path("src/app.py", expected_type="file"), "src/app.py")
        self.assertEqual(self.policy.safe_relative_path(self.root), ".")

    def test_rejects_parent_traversal_even_when_it_returns_inside_root(self) -> None:
        with self.assertRaises(PathPolicyError):
            self.policy.validate_file("src/../src/app.py")

    def test_rejects_external_absolute_path(self) -> None:
        outside = Path(self.temp_dir.name) / "outside.py"
        outside.write_text("secret\n", encoding="utf-8")
        with self.assertRaises(PathPolicyError):
            self.policy.validate_file(outside)

    def test_rejects_sensitive_names_case_insensitively(self) -> None:
        for relative in (
            ".env", ".env.local", ".git/config", "credentials-prod.json",
            "secrets-prod.yaml", "id_rsa_backup",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("sensitive\n", encoding="utf-8")
            with self.subTest(relative=relative), self.assertRaises(PathPolicyError):
                self.policy.validate_file(relative)

    def test_rejects_key_and_certificate_extensions(self) -> None:
        for name in ("private.KEY", "client.pem", "bundle.p12", "server.crt"):
            target = self.root / name
            target.write_text("credential\n", encoding="utf-8")
            with self.subTest(name=name), self.assertRaises(PathPolicyError):
                self.policy.validate_file(name)

    def test_rejects_vendor_and_generated_directories(self) -> None:
        for directory in ("vendor", "node_modules", "generated", "reports"):
            target = self.root / directory / "item.py"
            target.parent.mkdir(parents=True)
            target.write_text("generated\n", encoding="utf-8")
            with self.subTest(directory=directory), self.assertRaises(PathPolicyError):
                self.policy.validate_file(target)

    def test_rejects_wrong_expected_type(self) -> None:
        with self.assertRaises(PathPolicyError):
            self.policy.validate_file("src")
        with self.assertRaises(PathPolicyError):
            self.policy.validate_directory("src/app.py")

    def test_rejects_symlink_escape_when_supported(self) -> None:
        outside = Path(self.temp_dir.name) / "outside.txt"
        outside.write_text("secret\n", encoding="utf-8")
        link = self.root / "src" / "escape.txt"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError):
            self.skipTest("현재 환경에서 symlink 생성 권한을 사용할 수 없습니다.")

        with self.assertRaises(PathPolicyError):
            self.policy.validate_file(link)

    @unittest.skipUnless(os.name == "nt", "Windows junction/reparse 전용 검사")
    def test_rejects_windows_junction_escape_when_available(self) -> None:
        outside_dir = Path(self.temp_dir.name) / "outside-dir"
        outside_dir.mkdir()
        link = self.root / "junction"
        try:
            os.symlink(outside_dir, link, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("현재 환경에서 junction/reparse 생성 권한을 사용할 수 없습니다.")

        with self.assertRaises(PathPolicyError):
            self.policy.validate_directory(link)


if __name__ == "__main__":
    unittest.main()
