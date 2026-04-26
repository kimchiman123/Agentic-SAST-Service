"""
분석 결과 리포트 생성 모듈.
Agent가 반환한 취약점 데이터를 Markdown 형식의 보고서로 변환합니다.
"""
from datetime import datetime
from typing import Any, Dict, List
import re

# 심각도별 매핑 (이모지 제거, 텍스트 형태 사용)
SEVERITY_PREFIX = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
    "INFO": "[INFO]",
}

# 심각도 우선순위 (정렬용)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Semgrep 심각도 → 내부 심각도 매핑 (Semgrep은 ERROR/WARNING 등을 사용)
SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
}


def _normalize_severity(severity: str) -> str:
    """Semgrep 등 외부 도구의 심각도를 내부 체계(CRITICAL~INFO)로 정규화합니다."""
    sev = severity.upper().strip()
    if sev in SEVERITY_ORDER:
        return sev
    return SEMGREP_SEVERITY_MAP.get(sev, "INFO")


def _sort_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """심각도 기준으로 취약점을 정렬합니다."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 5)
    )

MAX_CODE_LINES = 15  # 코드 블록 최대 줄 수 (PDF 페이지 절약)


def _clean_code_block(code_str: Any) -> str:
    """LLM이 반환한 코드 스니펫에서 마크다운 백틱과 불필요한 텍스트를 제거하고 길이를 제한합니다."""
    if not isinstance(code_str, str):
        return str(code_str)
    code_str = code_str.strip()
    # 백틱 블록 마커 제거
    code_str = re.sub(r"```[a-zA-Z0-9_\-\+]*", "", code_str)
    code_str = re.sub(r"```", "", code_str)
    # LLM이 코드 블록 안에 섞어 넣는 마크다운 헤더/볼드 텍스트 제거
    code_str = re.sub(r"^\*\*[^*]+\*\*:?\s*$", "", code_str, flags=re.MULTILINE)
    code_str = re.sub(r"\n{3,}", "\n\n", code_str)
    code_str = code_str.strip()
    # 줄 수 제한
    code_lines = code_str.splitlines()
    if len(code_lines) > MAX_CODE_LINES:
        code_str = "\n".join(code_lines[:MAX_CODE_LINES]) + f"\n... ({len(code_lines) - MAX_CODE_LINES}줄 생략)"
    return code_str


def _calculate_score(findings: List[Dict[str, Any]]) -> int:
    """보안 점수를 가중 비율 기반으로 계산합니다 (0-100)."""
    tp_findings = [f for f in findings if f.get("is_true_positive", True)]
    
    if not tp_findings:
        return 100
    
    # 가중치 기반 위험도 산출 (취약점 수에 비례하되 0점 고착 방지)
    weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.0}
    total_weight = 0.0
    for f in tp_findings:
        sev = f.get("severity", "INFO").upper()
        total_weight += weights.get(sev, 0.0)
    
    # 로그 스케일 감점: 취약점이 많아도 0점에 고착되지 않음
    import math
    deduction = min(90, int(30 * math.log2(1 + total_weight)))
    
    return max(10, 100 - deduction)

def _build_executive_summary(findings: List[Dict[str, Any]]) -> str:
    """핵심 요약 대시보드(HTML 그리드)를 생성합니다."""
    score = _calculate_score(findings)
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    tp_findings = [f for f in findings if f.get("is_true_positive", True)]
    for f in tp_findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_count:
            severity_count[sev] += 1

    score_color = "#059669" if score >= 80 else "#d97706" if score >= 50 else "#e11d48"
    
    html = f"""
<div class="dashboard">
    <div class="score-card">
        <div class="score-label">SECURITY SCORE</div>
        <div class="score-value" style="color: {score_color}">{score}</div>
        <div class="score-bar-bg"><div class="score-bar-fill" style="width: {score}%; background: {score_color}"></div></div>
    </div>
    <div class="stats-grid">
        <div class="stat-card critical">
            <div class="stat-label">CRITICAL</div>
            <div class="stat-count">{severity_count['CRITICAL']}</div>
        </div>
        <div class="stat-card high">
            <div class="stat-label">HIGH</div>
            <div class="stat-count">{severity_count['HIGH']}</div>
        </div>
        <div class="stat-card medium">
            <div class="stat-label">MEDIUM</div>
            <div class="stat-count">{severity_count['MEDIUM']}</div>
        </div>
        <div class="stat-card info">
            <div class="stat-label">INFO/LOW</div>
            <div class="stat-count">{severity_count['INFO'] + severity_count['LOW']}</div>
        </div>
    </div>
</div>
"""
    return html


def _render_semgrep_finding(idx: int, finding: Dict[str, Any]) -> str:
    """Semgrep 검증 결과 단일 항목을 압축 레이아웃으로 렌더링합니다."""
    sev = finding.get("severity", "INFO")
    prefix = SEVERITY_PREFIX.get(sev, f"[{sev}]")
    is_tp = finding.get("is_true_positive", True)
    status = "TP" if is_tp else "FP"

    # 메타정보 한 줄 압축
    rule_id = finding.get('rule_id', 'N/A')
    file_path = finding.get('original_file', 'N/A')
    lines = [
        f"### {idx}. {prefix} {finding.get('title', '제목 없음')}",
        f"`{sev}` | `{status}` | `{rule_id}` | `{file_path}`",
        "",
        f"{finding.get('description', '설명 없음')}",
        "",
    ]
    
    # LOW/INFO는 설명만으로 충분
    if sev in ["LOW", "INFO"]:
        lines.append("---\n")
        return "\n".join(lines)

    # 오탐 사유 (FP인 경우만)
    if not is_tp and finding.get("false_positive_reason"):
        lines.append(f"> **오탐 사유:** {finding['false_positive_reason']}")
        lines.append("")

    # 분석 내역 (공격 시나리오만 출력, Taint는 생략하여 압축)
    if finding.get("exploit_scenario"):
        lines.append(f"> **공격 시나리오:** {finding['exploit_scenario']}")
        lines.append("")

    # 코드 블록: TP일 때만 표시 (오탐 건은 코드 생략)
    if is_tp and finding.get("affected_code"):
        lines.extend(["**취약 코드:**", "```", _clean_code_block(finding["affected_code"]), "```", ""])

    if is_tp and finding.get("remediation_code"):
        lines.extend(["**수정 코드:**", "```", _clean_code_block(finding["remediation_code"]), "```", ""])

    if finding.get("remediation_description"):
        lines.append(f"**수정 가이드:** {finding['remediation_description']}")
        lines.append("")

    if finding.get("isms_p_violation"):
        lines.append(f"> **ISMS-P:** {finding['isms_p_violation']}")
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


def _render_deep_finding(idx: int, finding: Dict[str, Any]) -> str:
    """심층 분석 결과 단일 항목을 압축 레이아웃으로 렌더링합니다."""
    sev = finding.get("severity", "INFO")
    prefix = SEVERITY_PREFIX.get(sev, f"[{sev}]")

    vuln_type = finding.get('vulnerability_type', 'N/A')
    file_path = finding.get('file_path', 'N/A')
    lines = [
        f"### {idx}. {prefix} {finding.get('title', '제목 없음')}",
        f"`{sev}` | `{vuln_type}` | `{file_path}`",
        "",
        f"{finding.get('description', '설명 없음')}",
        "",
    ]
    
    # LOW/INFO는 설명만으로 충분
    if sev in ["LOW", "INFO"]:
        lines.append("---\n")
        return "\n".join(lines)

    if finding.get("exploit_scenario"):
        lines.append(f"> **공격 시나리오:** {finding['exploit_scenario']}")
        lines.append("")

    if finding.get("affected_code"):
        lines.extend(["**취약 코드:**", "```", _clean_code_block(finding["affected_code"]), "```", ""])

    if finding.get("remediation_code"):
        lines.extend(["**수정 코드:**", "```", _clean_code_block(finding["remediation_code"]), "```", ""])

    if finding.get("remediation_description"):
        lines.append(f"**수정 가이드:** {finding['remediation_description']}")
        lines.append("")

    if finding.get("isms_p_violation"):
        lines.append(f"> **ISMS-P:** {finding['isms_p_violation']}")
        lines.append("")

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

    # 심각도 정규화 (Semgrep의 ERROR/WARNING → HIGH/MEDIUM 변환)
    for f in all_findings:
        f["severity"] = _normalize_severity(f.get("severity", "INFO"))

    # 출처별 분리
    semgrep_findings = [f for f in all_findings if f.get("source") == "semgrep_verified"]
    deep_findings = [f for f in all_findings if f.get("source") == "deep_analysis"]

    # 심각도별 정렬
    semgrep_findings = _sort_by_severity(semgrep_findings)
    deep_findings = _sort_by_severity(deep_findings)

    report_lines = [
        "<div class='report-cover'>",
        "# Security Analysis Report",
        f"<p class='report-meta'>Generated on {now} by <strong>Agentic-SAST-Guardian</strong></p>",
        "</div>",
        "",
        "## 1. Executive Summary",
        "",
        _build_executive_summary(all_findings),
        "",
    ]

    # ISMS-P 위반 요약 (상단부 이동)
    isms_violations = [
        f for f in all_findings
        if f.get("isms_p_violation") and f["isms_p_violation"] != "null"
    ]
    if isms_violations:
        report_lines.extend([
            "### 1.2 ISMS-P 컴플라이언스 위반 요약",
            "",
            f"이번 분석에서 총 **{len(isms_violations)}건**의 ISMS-P 인증기준 위반 또는 위반 의심 사례가 탐지되었습니다. 관련 부서는 본 리포트의 세부 항목을 검토 후 조치 요망.",
            "",
            "| # | ISMS-P 위반 핵심 내용 | 관련 취약점 | 심각도 |",
            "|---|-----------------------|------------|--------|",
        ])
        for i, v in enumerate(isms_violations, 1):
            title = v.get("title", "N/A")
            violation = v.get("isms_p_violation", "N/A")
            short_violation = violation if len(violation) < 50 else violation[:47] + "..."
            sev = v.get("severity", "N/A")
            report_lines.append(f"| {i} | {short_violation} | {title} | {sev} |")
        report_lines.append("")

    report_lines.append("<div class='page-break'></div>")
    report_lines.extend([
        "",
        "## 2. Detailed Findings",
        "",
    ])

    # Semgrep 검증 결과 섹션
    if semgrep_findings:
        report_lines.extend([
            "### 2.1 코드 정적 분석 결과",
            "",
        ])
        for i, finding in enumerate(semgrep_findings, 1):
            report_lines.append(_render_semgrep_finding(i, finding))

    # 심층 분석 결과 섹션
    if deep_findings:
        report_lines.extend([
            "### 2.2 비즈니스 로직 심층 분석 결과",
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
        "*본 리포트는 자동화 소스코드 취약점 점검을 통해 산출된 보안 감사 문서입니다.*",
        "*본 결과는 참고용이며 배포 전 보안 부서의 추가 검토가 필요할 수 있습니다.*",
    ])

    return "\n".join(report_lines)
