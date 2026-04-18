"""
Smart Context 생성 모듈.
Semgrep 스캔 결과를 바탕으로 취약점 주변 코드와 프로젝트 구조를 수집하고,
핵심 비즈니스 로직(인증/인가/결제 등) 파일을 별도로 추출합니다.
"""
import os
from typing import Any, Dict, List

# 보안상 중요한 핵심 비즈니스 로직 경로/키워드 패턴
CRITICAL_PATH_KEYWORDS = [
    "auth", "login", "session", "token", "jwt",
    "payment", "billing", "wallet", "transfer",
    "user", "account", "profile", "permission",
    "admin", "role", "password", "credential",
    "encrypt", "decrypt", "crypto", "hash",
    "api", "middleware", "gateway",
]

# 분석 제외 대상 (테스트, 설정, 정적 파일 등)
EXCLUDE_PATTERNS = [
    "__pycache__", ".git", "node_modules", ".venv", "venv",
    ".env", ".idea", ".vscode", "dist", "build",
    "test", "tests", "spec", "mock",
]

# 분석 대상 소스코드 확장자
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php",
    ".yaml", ".yml", ".tf", ".dockerfile",
}


def _build_directory_tree(target_dir: str, max_depth: int = 4) -> str:
    """프로젝트 디렉토리 구조를 텍스트 트리 형태로 변환합니다."""
    lines: List[str] = []

    def _walk(path: str, prefix: str, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(os.listdir(path))
        except PermissionError:
            return

        # 제외 대상 필터링
        entries = [
            e for e in entries
            if not any(ex in e.lower() for ex in EXCLUDE_PATTERNS)
        ]

        for i, entry in enumerate(entries):
            full_path = os.path.join(path, entry)
            connector = "└── " if i == len(entries) - 1 else "├── "
            lines.append(f"{prefix}{connector}{entry}")
            if os.path.isdir(full_path):
                extension = "    " if i == len(entries) - 1 else "│   "
                _walk(full_path, prefix + extension, depth + 1)

    lines.append(os.path.basename(target_dir) + "/")
    _walk(target_dir, "", 0)
    return "\n".join(lines)


def _read_file_lines(file_path: str) -> List[str]:
    """파일 내용을 줄 단위로 읽어옵니다."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except (FileNotFoundError, PermissionError):
        return []


def _extract_code_snippet(file_path: str, start_line: int, end_line: int, context_lines: int = 50) -> str:
    """취약점 위치 주변의 코드 스니펫을 추출합니다."""
    lines = _read_file_lines(file_path)
    if not lines:
        return ""

    # 0-indexed로 변환 후 앞뒤 context_lines만큼 확장
    begin = max(0, start_line - 1 - context_lines)
    end = min(len(lines), end_line + context_lines)

    snippet_lines: List[str] = []
    for i in range(begin, end):
        line_num = i + 1
        marker = " >>> " if start_line <= line_num <= end_line else "     "
        snippet_lines.append(f"{line_num:4d}{marker}{lines[i].rstrip()}")

    return "\n".join(snippet_lines)


def _is_critical_file(file_path: str) -> bool:
    """파일 경로가 보안상 핵심 비즈니스 로직에 해당하는지 판별합니다."""
    lower_path = file_path.lower().replace("\\", "/")
    return any(keyword in lower_path for keyword in CRITICAL_PATH_KEYWORDS)


class ContextExtractor:
    """
    2단계: Smart Context 생성을 담당하는 클래스.
    Semgrep 결과 기반 취약 지점 + 핵심 비즈니스 로직을 모두 수집합니다.
    """

    def __init__(self, context_lines: int = 50) -> None:
        self.context_lines = context_lines

    def extract_contexts(self, scan_results: Dict[str, Any], target_dir: str) -> List[Dict[str, Any]]:
        """
        Semgrep 스캔 결과에서 취약점 위치를 식별하고,
        해당 라인의 앞뒤 코드 스니펫과 프로젝트 구조를 맵핑합니다.

        Args:
            scan_results: Semgrep 스캔 결과 (JSON)
            target_dir: 분석 대상 디렉토리 경로

        Returns:
            추출된 컨텍스트 목록
        """
        abs_target = os.path.abspath(target_dir)
        tree = _build_directory_tree(abs_target)
        contexts: List[Dict[str, Any]] = []

        for finding in scan_results.get("results", []):
            file_path = finding.get("path", "")
            # Docker 내부 경로(/src/...) → 실제 로컬 경로로 변환
            if file_path.startswith("/src/"):
                file_path = os.path.join(abs_target, file_path[5:])
            elif not os.path.isabs(file_path):
                file_path = os.path.join(abs_target, file_path)

            start_line = finding.get("start", {}).get("line", 1)
            end_line = finding.get("end", {}).get("line", start_line)

            snippet = _extract_code_snippet(file_path, start_line, end_line, self.context_lines)
            if not snippet:
                continue

            context = {
                "type": "semgrep_finding",
                "rule_id": finding.get("check_id", "unknown"),
                "severity": finding.get("extra", {}).get("severity", "WARNING"),
                "message": finding.get("extra", {}).get("message", ""),
                "file_path": os.path.relpath(file_path, abs_target),
                "start_line": start_line,
                "end_line": end_line,
                "code_snippet": snippet,
                "project_tree": tree,
            }
            contexts.append(context)

        return contexts

    def extract_critical_files(self, target_dir: str) -> List[Dict[str, Any]]:
        """
        Semgrep 결과와 무관하게, 보안상 중요한 핵심 비즈니스 로직 파일을 수집합니다.
        (Tier 2 - 하이브리드 스캐닝: Semgrep이 놓칠 수 있는 논리적 취약점 탐지용)

        Args:
            target_dir: 분석 대상 디렉토리 경로

        Returns:
            핵심 파일의 전체 코드와 메타데이터 목록
        """
        abs_target = os.path.abspath(target_dir)
        critical_contexts: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(abs_target):
            # 제외 대상 디렉토리 스킵
            dirs[:] = [
                d for d in dirs
                if not any(ex in d.lower() for ex in EXCLUDE_PATTERNS)
            ]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SOURCE_EXTENSIONS:
                    continue

                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, abs_target)

                if not _is_critical_file(rel_path):
                    continue

                content = "".join(_read_file_lines(full_path))
                if not content.strip():
                    continue

                critical_contexts.append({
                    "type": "critical_logic",
                    "file_path": rel_path,
                    "content": content,
                    "size_bytes": os.path.getsize(full_path),
                })

        print(f"[+] 핵심 비즈니스 로직 파일 {len(critical_contexts)}개 식별 완료")
        return critical_contexts
