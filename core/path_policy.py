"""스캔 및 에이전트 도구에서 사용하는 파일 경로 경계 정책."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union


PathLike = Union[str, os.PathLike[str]]


class PathPolicyError(ValueError):
    """요청 경로가 스캔 경계를 위반할 때 발생합니다."""


class ScanPathPolicy:
    """하나의 스캔 루트 내부에서만 파일 접근을 허용합니다.

    ``Path.resolve(strict=True)``와 ``os.path.realpath``를 함께 사용해
    심볼릭 링크 및 Windows junction/reparse point를 가능한 범위에서
    실제 경로로 정규화합니다.
    """

    SENSITIVE_NAMES = frozenset(
        {
            ".aws", ".docker", ".env", ".git", ".kube", ".netrc", ".npmrc",
            ".pypirc", ".ssh", "credentials", "credentials.json", "id_dsa",
            "id_ecdsa", "id_ed25519", "id_rsa", "kubeconfig", "secrets",
            "secrets.json", "secrets.yaml", "secrets.yml",
        }
    )
    BLOCKED_DIRECTORY_NAMES = frozenset(
        {
            ".chroma_db",
            ".hg",
            ".svn",
            ".venv",
            "__pycache__",
            "artifacts",
            "build",
            "coverage",
            "dist",
            "generated",
            "node_modules",
            "reports",
            "vendor",
            "venv",
        }
    )
    BLOCKED_FILE_EXTENSIONS = frozenset(
        {
            ".asc",
            ".cer",
            ".crt",
            ".der",
            ".db",
            ".gpg",
            ".jks",
            ".key",
            ".keystore",
            ".p12",
            ".pem",
            ".pfx",
            ".pub",
            ".sqlite",
            ".sqlite3",
        }
    )

    def __init__(self, root: PathLike) -> None:
        root_path = Path(root).expanduser()
        try:
            resolved_root = self._real_resolve(root_path)
        except (OSError, RuntimeError) as exc:
            raise PathPolicyError("스캔 루트를 확인할 수 없습니다.") from exc

        if not resolved_root.is_dir():
            raise PathPolicyError("스캔 루트가 디렉터리가 아닙니다.")

        self.root = resolved_root

    @staticmethod
    def _real_resolve(path: Path) -> Path:
        """symlink와 Windows junction을 실제 경로로 최대한 정규화합니다."""
        resolved = path.resolve(strict=True)
        return Path(os.path.realpath(os.fspath(resolved))).resolve(strict=True)

    @staticmethod
    def _has_parent_traversal(path: Path) -> bool:
        return any(part == ".." for part in path.parts)

    def _relative_to_root(self, path: Path) -> Path:
        try:
            return path.relative_to(self.root)
        except ValueError as exc:
            raise PathPolicyError("스캔 루트 외부 경로는 허용되지 않습니다.") from exc

    @classmethod
    def _is_sensitive_name(cls, name: str) -> bool:
        lowered = name.casefold()
        return (
            lowered == ".env"
            or lowered.startswith(".env.")
            or lowered.startswith("credentials")
            or lowered.startswith("secrets")
            or lowered.startswith("id_rsa")
            or lowered.startswith("id_dsa")
            or lowered.startswith("id_ecdsa")
            or lowered.startswith("id_ed25519")
            or lowered in cls.SENSITIVE_NAMES
        )

    def _check_components(self, resolved: Path, relative: Path) -> None:
        parts = relative.parts
        if any(self._is_sensitive_name(part) for part in parts):
            raise PathPolicyError("민감 경로는 허용되지 않습니다.")

        directory_parts = parts if resolved.is_dir() else parts[:-1]
        blocked = self.BLOCKED_DIRECTORY_NAMES
        if any(part.casefold() in blocked for part in directory_parts):
            raise PathPolicyError("vendor/generated 경로는 허용되지 않습니다.")

        if resolved.is_file() and resolved.suffix.casefold() in self.BLOCKED_FILE_EXTENSIONS:
            raise PathPolicyError("키/인증서 파일은 허용되지 않습니다.")

    def resolve(self, candidate: PathLike) -> Path:
        """경계와 차단 규칙을 검증하고 실제 절대 경로를 반환합니다."""
        requested = Path(candidate).expanduser()
        if self._has_parent_traversal(requested):
            raise PathPolicyError("상위 경로 이동은 허용되지 않습니다.")

        combined = requested if requested.is_absolute() else self.root / requested
        try:
            resolved = self._real_resolve(combined)
        except (OSError, RuntimeError) as exc:
            raise PathPolicyError("경로를 확인할 수 없습니다.") from exc

        relative = self._relative_to_root(resolved)
        self._check_components(resolved, relative)
        return resolved

    def validate_file(self, candidate: PathLike) -> Path:
        """허용된 일반 파일인지 검증하고 실제 절대 경로를 반환합니다."""
        resolved = self.resolve(candidate)
        if not resolved.is_file():
            raise PathPolicyError("일반 파일이 아닙니다.")
        return resolved

    def validate_directory(self, candidate: PathLike) -> Path:
        """허용된 디렉터리인지 검증하고 실제 절대 경로를 반환합니다."""
        resolved = self.resolve(candidate)
        if not resolved.is_dir():
            raise PathPolicyError("디렉터리가 아닙니다.")
        return resolved

    def safe_relative_path(
        self,
        candidate: PathLike,
        *,
        expected_type: Optional[str] = None,
    ) -> str:
        """검증된 경로를 루트 기준 POSIX 형식 상대 경로로 반환합니다.

        ``expected_type``은 ``"file"``, ``"directory"`` 또는 ``None``만
        허용합니다.
        """
        if expected_type == "file":
            resolved = self.validate_file(candidate)
        elif expected_type == "directory":
            resolved = self.validate_directory(candidate)
        elif expected_type is None:
            resolved = self.resolve(candidate)
        else:
            raise ValueError("expected_type은 'file', 'directory', None 중 하나여야 합니다.")

        relative = self._relative_to_root(resolved)
        return relative.as_posix() or "."
