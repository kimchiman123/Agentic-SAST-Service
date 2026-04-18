"""
분석 결과 리포트 생성 모듈.
Agent가 반환한 취약점 데이터를 Markdown 형식의 보고서로 변환합니다.
"""
from datetime import datetime
from typing import Any, Dict, List
import re

# 심각도별 이모지 매핑
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}

# 심각도 우선순위 (정렬용)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sort_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """심각도 기준으로 취약점을 정렬합니다."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 5)
    )


def _clean_code_block(code_str: Any) -> str:
    """LLM이 반환한 코드 스니펫에서 불필요한 마크다운 백틱(```)을 안전하게 제거합니다."""
    if not isinstance(code_str, str):
        return str(code_str)
    code_str = code_str.strip()
    # 시작 부분의 ``` 및 언어 식별자 제거 (예: ```javascript)
    code_str = re.sub(r"^```[a-zA-Z0-9_\-\+]*\n", "", code_str)
    code_str = re.sub(r"^```", "", code_str)
    # 끝 부분의 ``` 제거
    code_str = re.sub(r"\n```$", "", code_str)
    code_str = re.sub(r"```$", "", code_str)
    return code_str.strip()


def _build_summary_table(findings: List[Dict[str, Any]]) -> str:
    """취약점 요약 테이블을 생성합니다."""
    severity_count: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    lines = [
        "| 심각도 | 개수 |",
        "|--------|------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_count.get(sev, 0)
        if count > 0:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev} | {count} |")

    lines.append(f"| **합계** | **{len(findings)}** |")
    return "\n".join(lines)


def _render_semgrep_finding(idx: int, finding: Dict[str, Any]) -> str:
    """Semgrep 검증 결과 단일 항목을 렌더링합니다."""
    sev = finding.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "")
    is_tp = finding.get("is_true_positive", True)
    status = "✅ True Positive" if is_tp else "❌ False Positive"

    lines = [
        f"### {idx}. {emoji} {finding.get('title', '제목 없음')}",
        f"- **심각도:** {sev}",
        f"- **판정:** {status}",
        f"- **규칙 ID:** `{finding.get('rule_id', 'N/A')}`",
        f"- **파일:** `{finding.get('original_file', 'N/A')}`",
        f"- **출처:** Semgrep 탐지 → Agent 검증",
        "",
        f"**설명:** {finding.get('description', '설명 없음')}",
        "",
    ]

    if not is_tp and finding.get("false_positive_reason"):
        lines.extend([
            "**💡 오탐 판단 사유:**",
            f"> {finding['false_positive_reason']}",
            "",
        ])

    if finding.get("taint_analysis"):
        lines.extend([
            "**🔄 데이터 흐름 추적 (Taint Analysis):**",
            f"> {finding['taint_analysis']}",
            "",
        ])

    if finding.get("exploit_scenario"):
        lines.extend([
            "**💥 공격 시나리오:**",
            f"> {finding['exploit_scenario']}",
            "",
        ])

    if finding.get("affected_code"):
        lines.extend([
            "**⚠️ 취약 원본 코드:**",
            "```",
            _clean_code_block(finding["affected_code"]),
            "```",
            "",
        ])

    if finding.get("remediation_code"):
        lines.extend([
            "**🛡️ 수정 패치 코드 (Remediation):**",
            "```",
            _clean_code_block(finding["remediation_code"]),
            "```",
            "",
        ])

    if finding.get("remediation_description"):
        lines.append(f"**수정 가이드:** {finding['remediation_description']}")
        lines.append("")

    if finding.get("isms_p_violation"):
        lines.extend([
            "**⚖️ ISMS-P 위반 사항:**",
            f"> {finding['isms_p_violation']}",
            "",
        ])

    lines.append("---\n")
    return "\n".join(lines)


def _render_deep_finding(idx: int, finding: Dict[str, Any]) -> str:
    """심층 분석 결과 단일 항목을 렌더링합니다."""
    sev = finding.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "")

    lines = [
        f"### {idx}. {emoji} {finding.get('title', '제목 없음')}",
        f"- **심각도:** {sev}",
        f"- **유형:** `{finding.get('vulnerability_type', 'N/A')}`",
        f"- **파일:** `{finding.get('file_path', 'N/A')}`",
        f"- **출처:** AI Agent 심층 분석 (비즈니스 로직 검사)",
        "",
        f"**설명:** {finding.get('description', '설명 없음')}",
        "",
    ]

    if finding.get("taint_analysis"):
        lines.extend([
            "**🔄 데이터 흐름 추적 (Taint Analysis):**",
            f"> {finding['taint_analysis']}",
            "",
        ])

    if finding.get("exploit_scenario"):
        lines.extend([
            "**💥 공격 시나리오:**",
            f"> {finding['exploit_scenario']}",
            "",
        ])

    if finding.get("affected_code"):
        lines.extend([
            "**⚠️ 취약 원본 코드:**",
            "```",
            _clean_code_block(finding["affected_code"]),
            "```",
            "",
        ])

    if finding.get("remediation_code"):
        lines.extend([
            "**🛡️ 수정 패치 코드 (Remediation):**",
            "```",
            _clean_code_block(finding["remediation_code"]),
            "```",
            "",
        ])

    if finding.get("remediation_description"):
        lines.append(f"**수정 가이드:** {finding['remediation_description']}")
        lines.append("")

    if finding.get("isms_p_violation"):
        lines.extend([
            "**⚖️ ISMS-P 위반 사항:**",
            f"> {finding['isms_p_violation']}",
            "",
        ])

    lines.append("---\n")
    return "\n".join(lines)


def format_report(all_findings: List[Dict[str, Any]]) -> str:
    """
    전체 분석 결과를 Markdown 보고서로 변환합니다.

    Args:
        all_findings: Agent가 반환한 취약점 리스트

    Returns:
        마크다운 포맷의 최종 리포트 텍스트
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 출처별 분리
    semgrep_findings = [f for f in all_findings if f.get("source") == "semgrep_verified"]
    deep_findings = [f for f in all_findings if f.get("source") == "deep_analysis"]

    # 심각도별 정렬
    semgrep_findings = _sort_by_severity(semgrep_findings)
    deep_findings = _sort_by_severity(deep_findings)

    report_lines = [
        "# 🛡️ Agentic-SAST-Guardian 보안 분석 리포트",
        "",
        f"**분석 일시:** {now}",
        f"**분석 도구:** Semgrep + OpenAI GPT Agent",
        "",
        "---",
        "",
        "## 📑 1. 경영진 요약 (Executive Summary)",
        "",
        "### 📊 1.1 발견된 취약점 통계 요약",
        "",
        _build_summary_table(all_findings),
        "",
    ]

    # ISMS-P 위반 요약 (상단부 이동)
    isms_violations = [
        f for f in all_findings
        if f.get("isms_p_violation") and f["isms_p_violation"] != "null"
    ]
    if isms_violations:
        report_lines.extend([
            "### ⚖️ 1.2 ISMS-P 컴플라이언스 총평",
            "",
            f"이번 분석에서 총 **{len(isms_violations)}건**의 ISMS-P 인증기준 위반 또는 위반 의심 사례가 탐지되었습니다. 개발팀은 본 리포트의 세부 항목을 참고하여 우선적으로 조치하시기 바랍니다.",
            "",
            "| # | ISMS-P 위반 핵심 내용 | 관련 취약점 | 심각도 |",
            "|---|-----------------------|------------|--------|",
        ])
        for i, v in enumerate(isms_violations, 1):
            title = v.get("title", "N/A")
            violation = v.get("isms_p_violation", "N/A")
            # 긴 위반 설명은 테이블에서 줄바꿈 방지를 위해 50자로 자름 처리
            short_violation = violation if len(violation) < 50 else violation[:47] + "..."
            sev = v.get("severity", "N/A")
            emoji = SEVERITY_EMOJI.get(sev, "")
            report_lines.append(f"| {i} | {short_violation} | {title} | {emoji} {sev} |")
        report_lines.append("")

    report_lines.extend([
        "---",
        "",
        "## 🔍 2. 세부 분석 결과 (Detailed Findings)",
        "",
    ])

    # Semgrep 검증 결과 섹션
    if semgrep_findings:
        report_lines.extend([
            "### 🛠️ 2.1 Semgrep 기본 탐지 결과 (AI 2차 검증됨)",
            "",
        ])
        for i, finding in enumerate(semgrep_findings, 1):
            report_lines.append(_render_semgrep_finding(i, finding))

    # 심층 분석 결과 섹션
    if deep_findings:
        report_lines.extend([
            "### 🧠 2.2 비즈니스 로직 심층 분석 결과",
            "",
        ])
        for i, finding in enumerate(deep_findings, 1):
            report_lines.append(_render_deep_finding(i, finding))

    # 결과 없음 처리
    if not all_findings:
        report_lines.extend([
            "현재 스캔 범위 내에서 보안 취약점이 발견되지 않았습니다.",
            "",
        ])

    report_lines.extend([
        "---",
        "",
        "*본 전체 리포트는 Agentic-SAST-Guardian 프로세스에 의해 자동 생성되었습니다.*",
        f"*ISMS-P 인증기준 안내서(2023.11.23) 기반 컴플라이언스 검증이 포함되었습니다.*",
    ])

    return "\n".join(report_lines)
