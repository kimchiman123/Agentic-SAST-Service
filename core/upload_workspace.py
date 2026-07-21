"""Safe, short-lived workspaces for ZIP and loose-file analysis inputs."""

from __future__ import annotations

import io
import os
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from core.config import UploadLimits
from core.path_policy import ScanPathPolicy


class UploadWorkspaceError(ValueError):
    pass


_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


@dataclass(frozen=True)
class UploadedFile:
    name: str
    data: bytes


class UploadWorkspace:
    """A caller-owned temporary directory that is removed on every exit path."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._closed = False

    @classmethod
    def create(cls) -> "UploadWorkspace":
        return cls(Path(tempfile.mkdtemp(prefix="agentic-sast-upload-")))

    def __enter__(self) -> "UploadWorkspace":
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if not self._closed:
            shutil.rmtree(self.root, ignore_errors=True)
            self._closed = True

    @staticmethod
    def _canonical_component(component: str) -> str:
        normalized = unicodedata.normalize("NFC", component).rstrip(". ")
        if not normalized or normalized in {".", ".."}:
            raise UploadWorkspaceError("Invalid upload path component.")
        stem = normalized.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED:
            raise UploadWorkspaceError("Windows reserved upload name is not allowed.")
        return normalized.casefold()

    @classmethod
    def _safe_relative(cls, name: str) -> tuple[Path, str]:
        if not isinstance(name, str) or not name or "\x00" in name:
            raise UploadWorkspaceError("Invalid upload filename.")
        normalized = unicodedata.normalize("NFC", name.replace("\\", "/"))
        path = PurePosixPath(normalized)
        if path.is_absolute() or any(":" in part or part in {"", ".", ".."} for part in path.parts):
            raise UploadWorkspaceError("Archive path traversal is not allowed.")
        canonical = "/".join(cls._canonical_component(part) for part in path.parts)
        return Path(*path.parts), canonical

    def _destination(self, relative: Path) -> Path:
        destination = (self.root / relative).resolve(strict=False)
        try:
            destination.relative_to(self.root.resolve())
        except ValueError as exc:
            raise UploadWorkspaceError("Upload path escapes the workspace.") from exc
        return destination

    @staticmethod
    def _zip_is_special(info: zipfile.ZipInfo) -> bool:
        mode = (info.external_attr >> 16) & 0xFFFF
        return bool(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))

    def extract_zip(self, archive: bytes, limits: UploadLimits) -> Path:
        if not archive or len(archive) > limits.max_upload_bytes:
            raise UploadWorkspaceError("Archive exceeds the upload size limit.")
        try:
            source = zipfile.ZipFile(io.BytesIO(archive))
        except zipfile.BadZipFile as exc:
            raise UploadWorkspaceError("Upload is not a valid ZIP archive.") from exc
        with source:
            entries = [item for item in source.infolist() if not item.is_dir()]
            if not entries:
                raise UploadWorkspaceError("Archive has no files to analyze.")
            if len(entries) > limits.max_files:
                raise UploadWorkspaceError("Archive contains too many files.")
            seen: set[str] = set()
            planned: list[tuple[zipfile.ZipInfo, Path]] = []
            total = 0
            for info in entries:
                relative, canonical = self._safe_relative(info.filename)
                if canonical in seen:
                    raise UploadWorkspaceError("Archive contains colliding normalized paths.")
                seen.add(canonical)
                if relative.suffix.casefold() == ".zip":
                    raise UploadWorkspaceError("Nested ZIP archives are not allowed.")
                if self._zip_is_special(info):
                    raise UploadWorkspaceError("Archive contains a symlink or special file.")
                if info.file_size > limits.max_file_bytes:
                    raise UploadWorkspaceError("Archive file exceeds the per-file limit.")
                if info.compress_size and info.file_size > info.compress_size * limits.max_compression_ratio:
                    raise UploadWorkspaceError("Archive compression ratio exceeds the limit.")
                total += info.file_size
                if total > limits.max_extracted_bytes:
                    raise UploadWorkspaceError("Archive extracted size exceeds the limit.")
                planned.append((info, relative))

            for info, relative in planned:
                destination = self._destination(relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with source.open(info, "r") as reader, destination.open("xb") as writer:
                    while chunk := reader.read(64 * 1024):
                        written += len(chunk)
                        if written > limits.max_file_bytes:
                            raise UploadWorkspaceError("Archive file exceeds the per-file limit.")
                        writer.write(chunk)
        self._validate_workspace()
        return self.root

    def write_loose_files(self, files: Iterable[UploadedFile], limits: UploadLimits) -> Path:
        files = list(files)
        if not files or len(files) > limits.max_files:
            raise UploadWorkspaceError("Upload must include between one and the maximum allowed files.")
        total = sum(len(item.data) for item in files)
        if total > limits.max_upload_bytes:
            raise UploadWorkspaceError("Uploads exceed the total size limit.")
        seen: set[str] = set()
        for item in files:
            basename = Path(item.name).name
            relative, canonical = self._safe_relative(basename)
            if canonical in seen:
                raise UploadWorkspaceError("Loose uploaded files have duplicate names.")
            seen.add(canonical)
            if len(item.data) > limits.max_file_bytes:
                raise UploadWorkspaceError("Uploaded file exceeds the per-file limit.")
            destination = self._destination(relative)
            destination.write_bytes(item.data)
        self._validate_workspace()
        return self.root

    def _validate_workspace(self) -> None:
        try:
            policy = ScanPathPolicy(self.root)
        except ValueError as exc:
            raise UploadWorkspaceError("Workspace validation failed.") from exc
        usable = 0
        for path in self.root.rglob("*"):
            if path.is_symlink() or not path.is_file():
                if path.is_symlink():
                    raise UploadWorkspaceError("Workspace cannot contain symlinks.")
                continue
            try:
                policy.validate_file(path)
            except ValueError:
                # Sensitive and unsupported files are intentionally excluded.
                continue
            usable += 1
        if usable == 0:
            raise UploadWorkspaceError("No analyzable files were uploaded.")


def validate_local_directory(path: str | Path, *, max_entries: int = 10_000) -> Path:
    """Validate local input without following symlinks or unbounded traversal."""
    policy = ScanPathPolicy(path)
    entries = 0
    for root, directories, files in os.walk(policy.root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
        entries += len(directories) + len(files)
        if entries > max_entries:
            raise UploadWorkspaceError("Local directory contains too many entries.")
    return policy.root
