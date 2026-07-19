"""분석 루트 밖으로 나갈 수 없는 read-only Agent 도구."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, List

from langchain_core.tools import tool

from core.path_policy import PathPolicyError, ScanPathPolicy


MAX_READ_LINES = 300
MAX_SEARCH_RESULTS = 100
MAX_QUERY_LENGTH = 200


def create_scoped_tools(policy: ScanPathPolicy) -> List[Any]:
    """한 스캔 루트에 고정된 도구 인스턴스를 생성합니다."""

    @tool("read_source")
    def read_source(file_path: str, start_line: int, end_line: int) -> str:
        """분석 루트 기준 상대 경로의 소스코드를 지정 라인 범위로 읽습니다."""
        if Path(file_path).is_absolute() or file_path.startswith(("~", "/", "\\")):
            return "[Error] 분석 루트 기준 상대 경로만 허용됩니다."
        try:
            resolved = policy.validate_file(file_path)
            start = max(1, int(start_line))
            requested_end = max(start, int(end_line))
            end = min(requested_end, start + MAX_READ_LINES - 1)

            with resolved.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()

            end = min(end, len(lines))
            if start > end:
                return "[Error] 요청한 라인 범위가 파일 길이를 벗어납니다."

            relative = policy.safe_relative_path(resolved, expected_type="file")
            output = [f"{relative}:{start + offset}: {line}" for offset, line in enumerate(lines[start - 1 : end])]
            if requested_end > end:
                output.append(f"\n[System] 한 번에 최대 {MAX_READ_LINES}라인만 반환합니다.")
            return "".join(output)
        except (PathPolicyError, TypeError, ValueError) as exc:
            return f"[Error] 허용되지 않은 파일 요청: {exc}"
        except OSError:
            return "[Error] 소스 코드 읽기에 실패했습니다."

    @tool("search_code")
    def search_code(query: str, dir_path: str = ".") -> str:
        """분석 루트 내부의 허용된 디렉터리에서 고정 문자열을 검색합니다."""
        if not query or len(query) > MAX_QUERY_LENGTH or "\x00" in query:
            return "[Error] 검색어 길이는 1~200자여야 합니다."
        if Path(dir_path).is_absolute() or dir_path.startswith(("~", "/", "\\")):
            return "[Error] 분석 루트 기준 상대 경로만 허용됩니다."

        try:
            directory = policy.validate_directory(dir_path)
        except PathPolicyError as exc:
            return f"[Error] 허용되지 않은 검색 경로: {exc}"

        command = [
            "rg", "-n", "--fixed-strings", "--no-heading", "--color", "never",
            "--glob", "!.env*", "--glob", "!.git/**", "--glob", "!node_modules/**",
            "--glob", "!vendor/**", "--glob", "!reports/**", "--glob", "!generated/**",
            "--glob", "!.ssh/**", "--glob", "!.aws/**", "--glob", "!.kube/**",
            "--glob", "!.npmrc", "--glob", "!.pypirc", "--glob", "!.netrc",
            "--glob", "!credentials*", "--glob", "!secrets*", "--glob", "!id_rsa",
            "--glob", "!*.key", "--glob", "!*.pem", "--glob", "!*.p12", "--glob", "!*.pfx",
            query, ".",
        ]
        try:
            result = subprocess.run(
                command, cwd=directory, capture_output=True, text=True,
                encoding="utf-8", errors="ignore", timeout=10,
            )
        except FileNotFoundError:
            return "[Warning] ripgrep(rg)이 설치되어 있지 않습니다."
        except subprocess.TimeoutExpired:
            return "[Error] 코드 검색 시간이 10초를 초과했습니다."

        if result.returncode not in (0, 1):
            return "[Error] 코드 검색 실행에 실패했습니다."
        if not result.stdout.strip():
            return f"[Result] '{query}' 검색 결과가 없습니다."

        safe_lines = []
        for raw_line in result.stdout.splitlines():
            raw_path = raw_line.split(":", 1)[0]
            try:
                policy.validate_file(directory / raw_path)
            except PathPolicyError:
                continue
            relative_dir = policy.safe_relative_path(directory, expected_type="directory")
            prefix = "" if relative_dir == "." else f"{relative_dir}/"
            safe_lines.append(prefix + raw_line)
            if len(safe_lines) >= MAX_SEARCH_RESULTS:
                break
        return "\n".join(safe_lines) or f"[Result] '{query}' 검색 결과가 없습니다."

    return [read_source, search_code]
