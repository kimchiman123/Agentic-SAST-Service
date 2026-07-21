import io
import zipfile

import pytest

from core.config import UploadLimits
from core.upload_workspace import UploadWorkspace, UploadWorkspaceError, UploadedFile


def _zip(entries: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return stream.getvalue()


def test_zip_traversal_is_rejected_and_workspace_is_cleaned() -> None:
    workspace = UploadWorkspace.create()
    try:
        with pytest.raises(UploadWorkspaceError):
            workspace.extract_zip(_zip({"../escape.py": b"print(1)"}), UploadLimits())
    finally:
        root = workspace.root
        workspace.cleanup()
    assert not root.exists()


def test_zip_case_collision_is_rejected() -> None:
    with UploadWorkspace.create() as workspace:
        with pytest.raises(UploadWorkspaceError):
            workspace.extract_zip(_zip({"src/App.py": b"a", "src/app.py": b"b"}), UploadLimits())


def test_loose_files_reject_duplicate_basename() -> None:
    with UploadWorkspace.create() as workspace:
        with pytest.raises(UploadWorkspaceError):
            workspace.write_loose_files([UploadedFile("a/test.py", b"a"), UploadedFile("b/test.py", b"b")], UploadLimits())
