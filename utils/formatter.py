"""
분석 결과 리포트 생성 모듈.
Agent가 반환한 취약점 데이터를 Markdown 형식의 보고서로 변환합니다.
"""
from datetime import datetime
from typing import Any, Dict, List

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

    if finding.get("exploit_scenario"):
        lines.extend([
            "**공격 시나리오:**",
            f"> {finding['exploit_scenario']}",
            "",
        ])

    if finding.get("affected_code"):
        lines.extend([
            "**취약 코드:**",
            "```",
            finding["affected_code"],
            "```",
            "",
        ])

    if finding.get("remediation_code"):
        lines.extend([
            "**수정 코드:**",
            "```",
            finding["remediation_code"],
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

    if finding.get("exploit_scenario"):
        lines.extend([
            "**공격 시나리오:**",
            f"> {finding['exploit_scenario']}",
            "",
        ])

    if finding.get("affected_code"):
        lines.extend([
            "**취약 코드:**",
            "```",
            finding["affected_code"],
            "```",
            "",
        ])

    if finding.get("remediation_code"):
        lines.extend([
            "**수정 코드:**",
            "```",
            finding["remediation_code"],
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
        f"**분석 도구:** Semgrep + OpenAI GPT-5.4-mini Agent",
        "",
        "---",
        "",
        "## 📊 취약점 요약",
        "",
        _build_summary_table(all_findings),
        "",
    ]

    # Semgrep 검증 결과 섹션
    if semgrep_findings:
        report_lines.extend([
            "---",
            "",
            "## 🔍 Semgrep 탐지 결과 (Agent 검증 완료)",
            "",
        ])
        for i, finding in enumerate(semgrep_findings, 1):
            report_lines.append(_render_semgrep_finding(i, finding))

    # 심층 분석 결과 섹션
    if deep_findings:
        report_lines.extend([
            "---",
            "",
            "## 🧠 AI 심층 분석 결과 (비즈니스 로직 취약점)",
            "",
        ])
        for i, finding in enumerate(deep_findings, 1):
            report_lines.append(_render_deep_finding(i, finding))

    # 결과 없음
    if not all_findings:
        report_lines.extend([
            "---",
            "",
            "## ✅ 분석 결과",
            "",
            "현재 스캔 범위 내에서 보안 취약점이 발견되지 않았습니다.",
            "",
        ])

    # ISMS-P 컴플라이언스 요약 섹션
    isms_violations = [
        f for f in all_findings
        if f.get("isms_p_violation") and f["isms_p_violation"] != "null"
    ]
    if isms_violations:
        report_lines.extend([
            "---",
            "",
            "## ⚖️ ISMS-P 컴플라이언스 위반 요약",
            "",
            f"총 **{len(isms_violations)}건**의 ISMS-P 인증기준 위반이 감지되었습니다.",
            "",
            "| # | 위반 항목 | 관련 취약점 | 심각도 |",
            "|---|-----------|------------|--------|",
        ])
        for i, v in enumerate(isms_violations, 1):
            title = v.get("title", "N/A")
            violation = v.get("isms_p_violation", "N/A")
            sev = v.get("severity", "N/A")
            emoji = SEVERITY_EMOJI.get(sev, "")
            report_lines.append(f"| {i} | {violation} | {title} | {emoji} {sev} |")
        report_lines.append("")

    report_lines.extend([
        "---",
        "",
        "*본 리포트는 Agentic-SAST-Guardian에 의해 자동 생성되었습니다.*",
        f"*ISMS-P 인증기준 안내서(2023.11.23) 기반 컴플라이언스 검증 포함*",
    ])

    return "\n".join(report_lines)
