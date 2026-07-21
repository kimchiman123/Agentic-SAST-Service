"""
Semgrep 정적 분석 실행 모듈.
Docker를 이용해 Semgrep을 실행하고 결과를 JSON으로 파싱합니다.
"""
import subprocess
import json
import os
from typing import Any, Dict, List, Optional

from core.path_policy import PathPolicyError, ScanPathPolicy


class SemgrepRunner:
    """
    1단계: Fast Scanning을 담당하는 클래스.
    Docker를 이용해 Semgrep을 실행하고 결과를 파싱합니다.
    """

    # Semgrep Docker 이미지
    SEMGREP_IMAGE = "returntocorp/semgrep"
    # 기본 Semgrep 규칙셋 (OWASP, 보안 관련 자동 탐지)
    DEFAULT_RULES = "p/default"

    def __init__(self, policy: ScanPathPolicy, rules: str = DEFAULT_RULES) -> None:
        self.policy = policy
        self.rules = rules

    def _check_docker_available(self) -> bool:
        """Docker 실행 가능 여부를 확인합니다."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=15, text=True, encoding="utf-8", errors="ignore"
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_scan(self, target_path: str) -> Optional[Dict[str, Any]]:
        """
        주어진 타겟 디렉토리에 대해 Docker로 Semgrep을 실행합니다.

        Args:
            target_path: 스캔할 대상 디렉토리 경로

        Returns:
            Semgrep 실행 결과(JSON 파싱된 딕셔너리) 또는 실패 시 None
        """
        try:
            abs_path = str(self.policy.validate_directory(target_path))
        except PathPolicyError:
            print("[!] 오류: 허용되지 않은 타겟 경로입니다.")
            return None

        if not self._check_docker_available():
            print("[!] 오류: Docker가 설치되지 않았거나 실행 중이 아닙니다.")
            return None

        # Windows 경로를 Docker 마운트용으로 변환 (C:\path -> /c/path)
        docker_mount_path = abs_path.replace("\\", "/")
        if len(docker_mount_path) >= 2 and docker_mount_path[1] == ":":
            drive = docker_mount_path[0].lower()
            docker_mount_path = f"/{drive}{docker_mount_path[2:]}"

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{docker_mount_path}:/src:ro",
            self.SEMGREP_IMAGE,
            "semgrep", "scan",
            "--config", self.rules,
            "--json",
            "--exclude", ".env*",
            "--exclude", ".git",
            "--exclude", "node_modules",
            "--exclude", "vendor",
            "--exclude", "reports",
            "--exclude", "generated",
            "--exclude", ".ssh",
            "--exclude", ".aws",
            "--exclude", ".kube",
            "--exclude", "credentials*",
            "--exclude", "secrets*",
            "--exclude", "id_rsa",
            "--exclude", "*.key",
            "--exclude", "*.pem",
            "--exclude", "*.p12",
            "--exclude", "*.pfx",
            "--exclude", "*.db",
            "--exclude", "*.sqlite*",
            "/src"
        ]

        print(f"[*] Semgrep 실행 중... (규칙: {self.rules})")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=300
            )

            # Semgrep은 취약점 발견 시 exit code 1을 반환할 수 있음
            if result.returncode not in (0, 1):
                print(f"[!] Semgrep 실행 실패 (exit code: {result.returncode})")
                print("[!] Semgrep 상세 오류는 로컬 debug 로그에서만 확인하세요.")
                return None

            scan_data = json.loads(result.stdout)
            findings = scan_data.get("results", [])
            print(f"[+] Semgrep 스캔 완료: {len(findings)}개 취약점 발견")

            return scan_data

        except subprocess.TimeoutExpired:
            print("[!] 오류: Semgrep 실행 시간이 초과되었습니다 (5분 제한).")
            return None
        except json.JSONDecodeError as e:
            print(f"[!] 오류: Semgrep 결과 JSON 파싱 실패 ({type(e).__name__})")
            return None
        except Exception as e:
            print(f"[!] 오류: Semgrep 실행 중 예외 발생 ({type(e).__name__})")
            return None

    def parse_findings(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Semgrep JSON 결과에서 취약점 정보만 추출하여 정규화합니다.

        Args:
            scan_data: Semgrep 원본 JSON 결과

        Returns:
            정규화된 취약점 딕셔너리 리스트
        """
        findings: List[Dict[str, Any]] = []

        for result in scan_data.get("results", []):
            finding = {
                "rule_id": result.get("check_id", "unknown"),
                "severity": result.get("extra", {}).get("severity", "WARNING"),
                "message": result.get("extra", {}).get("message", ""),
                "file_path": result.get("path", ""),
                "start_line": result.get("start", {}).get("line", 0),
                "end_line": result.get("end", {}).get("line", 0),
                "code_snippet": result.get("extra", {}).get("lines", ""),
                "metadata": result.get("extra", {}).get("metadata", {}),
            }
            findings.append(finding)

        return findings
