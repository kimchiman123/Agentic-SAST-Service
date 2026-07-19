"""로컬 UI와 CLI가 공유하는 민감 설정 처리."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path

import portalocker
from dotenv import set_key


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ENV_FILE = PROJECT_ROOT / ".env"
_ENV_LOCK = threading.Lock()
_MAX_ENV_BYTES = 64 * 1024


class ConfigError(ValueError):
    """안전하게 설정을 적용할 수 없을 때 발생합니다."""


def validate_openai_api_key(api_key: str) -> str:
    """로그에 키를 노출하지 않고 기본 형식과 주입 문자를 검증합니다."""
    if not isinstance(api_key, str):
        raise ConfigError("API 키 형식이 올바르지 않습니다.")
    normalized = api_key.strip()
    if normalized != api_key or any(character in normalized for character in ("\r", "\n", "\x00")):
        raise ConfigError("API 키에 허용되지 않는 문자가 있습니다.")
    if not normalized.startswith("sk-") or not 20 <= len(normalized) <= 512:
        raise ConfigError("OpenAI API 키 형식이 올바르지 않습니다.")
    if not re.fullmatch(r"sk-[A-Za-z0-9_.-]+", normalized):
        raise ConfigError("API 키에 허용되지 않는 문자가 있습니다.")
    return normalized


def configure_openai_api_key(api_key: str, *, persist: bool = False) -> str:
    """키를 현재 프로세스에 적용하고, 명시적 선택 시에만 `.env`에 저장합니다."""
    normalized = validate_openai_api_key(api_key)
    if persist:
        _persist_project_env(normalized)
    return normalized


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_existing_env(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or _is_reparse_point(path) or not path.is_file():
        raise ConfigError("안전하지 않은 .env 파일은 수정할 수 없습니다.")
    if path.stat(follow_symlinks=False).st_nlink > 1:
        raise ConfigError("hardlink로 연결된 .env 파일은 수정할 수 없습니다.")
    if path.stat().st_size > _MAX_ENV_BYTES:
        raise ConfigError(".env 파일이 너무 커서 안전하게 수정할 수 없습니다.")
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError(".env 파일을 읽을 수 없습니다.") from exc
    if "\x00" in content:
        raise ConfigError(".env 파일 형식이 올바르지 않습니다.")
    if sum(1 for line in content.splitlines() if line.lstrip().startswith("OPENAI_API_KEY=")) > 1:
        raise ConfigError("중복된 API 키 설정을 자동 수정할 수 없습니다.")


def _persist_project_env(api_key: str) -> None:
    env_path = PROJECT_ENV_FILE
    if env_path.parent.resolve() != PROJECT_ROOT.resolve() or env_path.name != ".env":
        raise ConfigError("허용되지 않은 설정 경로입니다.")
    if (PROJECT_ROOT / ".git").exists():
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", ".env"],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", "--", ".env"],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        if tracked.returncode == 0 or ignored.returncode != 0:
            raise ConfigError("Git에서 안전하게 제외되지 않은 .env에는 저장할 수 없습니다.")

    temporary_path: Path | None = None
    lock_directory = PROJECT_ROOT / ".runtime"
    lock_directory.mkdir(exist_ok=True)
    with _ENV_LOCK, portalocker.Lock(str(lock_directory / "env.lock"), mode="a", timeout=5):
        _validate_existing_env(env_path)
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".env.", suffix=".tmp", dir=str(PROJECT_ROOT), text=True
            )
            os.close(descriptor)
            temporary_path = Path(temporary_name)
            if env_path.exists():
                shutil.copyfile(env_path, temporary_path)
            set_key(str(temporary_path), "OPENAI_API_KEY", api_key, quote_mode="always")
            with temporary_path.open("ab") as handle:
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temporary_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            _validate_existing_env(env_path)
            os.replace(temporary_path, env_path)
            temporary_path = None
        except (OSError, ValueError) as exc:
            raise ConfigError("API 키를 .env에 저장하지 못했습니다.") from exc
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
