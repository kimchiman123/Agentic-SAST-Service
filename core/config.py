"""로컬 UI와 CLI가 공유하는 민감 설정 처리."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

import portalocker
from dotenv import set_key


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ENV_FILE = PROJECT_ROOT / ".env"
_ENV_LOCK = threading.Lock()
_MAX_ENV_BYTES = 64 * 1024


@dataclass(frozen=True)
class BatchLimits:
    max_items: int = 8
    max_chars: int = 24_000
    max_input_tokens: int = 12_000
    max_output_tokens: int = 4_000


@dataclass(frozen=True)
class UploadLimits:
    max_upload_bytes: int = 25 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_files: int = 500
    max_extracted_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: int = 100


@dataclass(frozen=True)
class RuntimeSettings:
    """One validated, immutable configuration snapshot for a scan run."""

    provider: str
    model: str
    api_key: str | None
    batch: BatchLimits
    upload: UploadLimits
    max_llm_requests: int
    max_semgrep_findings: int
    nvidia_context_window_tokens: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "RuntimeSettings":
        values = os.environ if environ is None else environ

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            raw = values.get(name)
            if raw is None or raw == "":
                return default
            if not raw.isascii() or not raw.isdecimal():
                raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}.")
            value = int(raw)
            if not minimum <= value <= maximum:
                raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}.")
            return value

        # Keep one narrowly-scoped compatibility alias for an existing project
        # configuration typo.  The value is never copied to the process
        # environment or logged; this only lets the validated runtime snapshot
        # use it as if it had been named correctly.
        api_key = (
            values.get("NVIDIA_API_KEY")
            or values.get("NVDIA_API_KEY")
            or values.get("OPENAI_API_KEY")
        )
        if api_key:
            api_key = validate_llm_api_key(api_key)
        provider = "nvidia" if api_key and api_key.startswith("nvapi-") else "openai"
        default_model = "openai/gpt-oss-120b" if provider == "nvidia" else "gpt-5.4-mini"
        model_name = values.get("NVIDIA_MODEL" if provider == "nvidia" else "OPENAI_MODEL", default_model)
        if not model_name or len(model_name) > 200 or any(char in model_name for char in "\r\n\x00"):
            raise ConfigError("Configured LLM model name is invalid.")

        batch = BatchLimits(
            max_items=integer("SAST_BATCH_MAX_ITEMS", 8, 1, 32),
            max_chars=integer("SAST_BATCH_MAX_CHARS", 24_000, 1_000, 100_000),
            max_input_tokens=integer("SAST_BATCH_INPUT_TOKENS", 12_000, 1_000, 64_000),
            max_output_tokens=integer("SAST_BATCH_OUTPUT_TOKENS", 4_000, 512, 16_000),
        )
        upload = UploadLimits(
            max_upload_bytes=integer("SAST_UPLOAD_MAX_MIB", 25, 1, 100) * 1024 * 1024,
            max_file_bytes=integer("SAST_UPLOAD_FILE_MAX_MIB", 2, 1, 20) * 1024 * 1024,
            max_files=integer("SAST_UPLOAD_MAX_FILES", 500, 1, 5_000),
            max_extracted_bytes=integer("SAST_UPLOAD_EXTRACTED_MAX_MIB", 100, 1, 500) * 1024 * 1024,
        )
        context_window = integer("NVIDIA_CONTEXT_WINDOW_TOKENS", 32_768, 8_192, 1_048_576)
        if batch.max_input_tokens + batch.max_output_tokens > context_window:
            raise ConfigError("NVIDIA_CONTEXT_WINDOW_TOKENS must cover batch input and output token limits.")
        return cls(
            provider=provider,
            model=model_name,
            api_key=api_key,
            batch=batch,
            upload=upload,
            max_llm_requests=integer("SAST_MAX_LLM_REQUESTS", 250, 1, 1_000),
            max_semgrep_findings=integer("SAST_MAX_SEMGREP_FINDINGS", 5_000, 100, 50_000),
            nvidia_context_window_tokens=context_window,
        )

    def with_api_key(self, api_key: str | None) -> "RuntimeSettings":
        """Return a run-local override without mutating process environment."""
        if api_key is None or api_key == "":
            return replace(self, api_key=None)
        normalized = validate_llm_api_key(api_key)
        provider = "nvidia" if normalized.startswith("nvapi-") else "openai"
        model = self.model
        if provider != self.provider:
            model = "openai/gpt-oss-120b" if provider == "nvidia" else "gpt-5.4-mini"
        return replace(self, api_key=normalized, provider=provider, model=model)


class ConfigError(ValueError):
    """안전하게 설정을 적용할 수 없을 때 발생합니다."""


def validate_llm_api_key(api_key: str) -> str:
    """OpenAI 또는 NVIDIA 키의 기본 형식과 주입 문자를 검증합니다."""
    if not isinstance(api_key, str):
        raise ConfigError("API 키 형식이 올바르지 않습니다.")
    normalized = api_key.strip()
    if normalized != api_key or any(character in normalized for character in ("\r", "\n", "\x00")):
        raise ConfigError("API 키에 허용되지 않는 문자가 있습니다.")
    if not 20 <= len(normalized) <= 512:
        raise ConfigError("API 키 형식이 올바르지 않습니다.")
    if not re.fullmatch(r"(?:sk|nvapi)-[A-Za-z0-9_.-]+", normalized):
        raise ConfigError("API 키에 허용되지 않는 문자가 있습니다.")
    return normalized


def validate_openai_api_key(api_key: str) -> str:
    """기존 OpenAI 전용 호출자를 위한 호환 검증 함수입니다."""
    normalized = validate_llm_api_key(api_key)
    if not normalized.startswith("sk-"):
        raise ConfigError("OpenAI API 키 형식이 올바르지 않습니다.")
    return normalized


def configure_llm_api_key(api_key: str, *, persist: bool = False) -> str:
    """LLM 키를 검증하고, 명시적 선택 시 공급자별 환경 변수로 저장합니다."""
    normalized = validate_llm_api_key(api_key)
    variable_name = "NVIDIA_API_KEY" if normalized.startswith("nvapi-") else "OPENAI_API_KEY"
    if persist:
        _persist_project_env(normalized, variable_name)
    return normalized


def configure_openai_api_key(api_key: str, *, persist: bool = False) -> str:
    """키를 현재 프로세스에 적용하고, 명시적 선택 시에만 `.env`에 저장합니다."""
    normalized = validate_openai_api_key(api_key)
    if persist:
        _persist_project_env(normalized, "OPENAI_API_KEY")
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
    for variable_name in ("OPENAI_API_KEY", "NVIDIA_API_KEY"):
        if sum(1 for line in content.splitlines() if line.lstrip().startswith(f"{variable_name}=")) > 1:
            raise ConfigError("중복된 API 키 설정을 자동 수정할 수 없습니다.")


def _persist_project_env(api_key: str, variable_name: str) -> None:
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
            set_key(str(temporary_path), variable_name, api_key, quote_mode="always")
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
