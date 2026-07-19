"""
Agentic-SAST-Guardian 메인 엔트리포인트.
CLI로 타겟 디렉토리를 지정하면 자동으로 정적 분석 → Agent 심층 분석 → 리포트 생성을 수행합니다.
"""
import argparse
import sys
import os
import time
from typing import Any, Dict, List

from dotenv import load_dotenv

from core.scanner import SemgrepRunner
from core.context_builder import ContextExtractor
from core.agent import OpenAIAgent
from core.isms_rag import ISMSKnowledgeBase
from core.path_policy import ScanPathPolicy
from utils.formatter import format_report
from utils.pdf_exporter import export_pdf


def _fmt_elapsed(seconds: float) -> str:
    """초 단위 시간을 사람이 읽기 좋은 형식으로 변환합니다."""
    if seconds < 60:
        return f"{seconds:.1f}초"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}분 {secs:.1f}초"


def run_pipeline(target_path: str) -> None:
    """보안 분석 파이프라인을 순차적으로 실행합니다."""

    abs_target = os.path.abspath(target_path)
    if not os.path.isdir(abs_target):
        print(f"[!] 오류: 경로가 존재하지 않습니다 -> {abs_target}")
        sys.exit(1)
    path_policy = ScanPathPolicy(abs_target)

    pipeline_start = time.time()

    print("=" * 60)
    print("  Agentic-SAST-Guardian v1.0")
    print("  AI 기반 정적 보안 분석 도구")
    print("=" * 60)
    print(f"[*] 타겟 디렉토리: {abs_target}\n")

    # ──────────────────────────────────────
    #  STEP 1: Semgrep 정적 분석 (Tier 1)
    # ──────────────────────────────────────
    phase_start = time.time()
    print("[Phase 1] Semgrep 정적 분석 실행 중...")
    scanner = SemgrepRunner(path_policy)
    scan_results = scanner.run_scan(abs_target)

    semgrep_contexts: List[Dict[str, Any]] = []
    if scan_results:
        context_builder = ContextExtractor(path_policy)
        semgrep_contexts = context_builder.extract_contexts(scan_results, abs_target)
        print(f"[+] Semgrep 컨텍스트 {len(semgrep_contexts)}개 추출 완료 ({_fmt_elapsed(time.time() - phase_start)})\n")
    else:
        print(f"[*] Semgrep에서 탐지된 취약점이 없거나 실행에 실패했습니다. ({_fmt_elapsed(time.time() - phase_start)})\n")

    # ──────────────────────────────────────
    #  STEP 2: ISMS-P RAG 지식베이스 초기화
    # ──────────────────────────────────────
    phase_start = time.time()
    print("[Phase 2] ISMS-P 지식베이스 초기화 중...")
    isms_kb = ISMSKnowledgeBase()
    isms_kb.ensure_ready()
    print(f"[+] 지식베이스 초기화 완료 ({_fmt_elapsed(time.time() - phase_start)})\n")

    # ──────────────────────────────────────
    #  STEP 3: 핵심 비즈니스 로직 수집 (Tier 2)
    # ──────────────────────────────────────
    phase_start = time.time()
    print("[Phase 3] 핵심 비즈니스 로직 파일 수집 중...")
    context_builder = ContextExtractor(path_policy)
    critical_files = context_builder.extract_critical_files(abs_target)
    print(f"[+] 파일 수집 완료 ({_fmt_elapsed(time.time() - phase_start)})\n")

    # ──────────────────────────────────────
    #  STEP 3.5: OSV 외부 의존성 취약점 스캔 (SCA)
    # ──────────────────────────────────────
    import core.tools.osv_checker as osv_checker
    phase_start = time.time()
    print("[Phase 3.5] OSV.dev 모듈 트리 스캔 및 취약점 조회 중...")
    osv_vulns = osv_checker.scan_dependencies(abs_target, path_policy)
    if osv_vulns:
        print(f"  [!] 의존성 취약점 내역이 발견되었습니다. Agent 컨텍스트에 주입 중... ({_fmt_elapsed(time.time() - phase_start)})\n")
    else:
        print(f"  [+] 알려진 의존성 취약점 없음. ({_fmt_elapsed(time.time() - phase_start)})\n")

    # 코드 컨텍스트와 의존성 모두 없을 때만 종료합니다.
    if not semgrep_contexts and not critical_files and not osv_vulns:
        print("[-] 분석할 대상이 없습니다. 종료합니다.")
        return

    # ──────────────────────────────────────
    #  STEP 4: Agent 심층 분석 (ISMS-P RAG 연동)
    # ──────────────────────────────────────
    phase_start = time.time()
    print("[Phase 4] AI Agent 심층 분석 실행 중...")
    agent = OpenAIAgent(isms_kb=isms_kb, osv_vulns=osv_vulns, target_root=abs_target)

    all_findings: List[Dict[str, Any]] = []
    for vulnerability in osv_vulns:
        all_findings.append({
            "source": "osv",
            "is_true_positive": True,
            "severity": "HIGH",
            "title": f"취약한 의존성: {vulnerability.get('package', 'unknown')}",
            "description": vulnerability.get("summary", "OSV에서 알려진 취약점이 확인되었습니다."),
            "vulnerability_type": "Supply Chain",
            "file_path": "package.json",
            "affected_code": f"{vulnerability.get('package', '')}@{vulnerability.get('version', '')}",
            "remediation_description": "OSV 권고 버전 또는 최신 안전 버전으로 업데이트하세요.",
            "decision_tree": ["의존성 manifest 확인", "OSV 취약점 ID 확인", str(vulnerability.get("cve_id", ""))],
        })

    # 4-1: Semgrep 결과 검증 (오탐 필터링 + 재평가)
    if semgrep_contexts:
        tier_start = time.time()
        print("  [Tier 1] Semgrep 탐지 결과 검증 중...")
        semgrep_findings = agent.analyze_semgrep_findings(semgrep_contexts)
        all_findings.extend(semgrep_findings)
        print(f"  [+] Semgrep 검증 완료: {len(semgrep_findings)}개 실제 취약점 확인 ({_fmt_elapsed(time.time() - tier_start)})\n")

    # 4-2: 핵심 로직 심층 분석 (논리적 취약점 탐지)
    if critical_files:
        tier_start = time.time()
        print("  [Tier 2] 핵심 비즈니스 로직 심층 분석 중...")
        deep_findings = agent.analyze_critical_logic(critical_files)
        all_findings.extend(deep_findings)
        print(f"  [+] 심층 분석 완료: {len(deep_findings)}개 논리적 취약점 발견 ({_fmt_elapsed(time.time() - tier_start)})\n")

    all_findings = all_findings[:200]
    budget_stop_reason = agent.budget.stop_reason()
    if budget_stop_reason:
        print(f"  [!] 분석 예산에 도달하여 부분 결과를 생성합니다: {budget_stop_reason}")

    print(f"[+] Phase 4 완료 ({_fmt_elapsed(time.time() - phase_start)})")

    # ──────────────────────────────────────
    #  STEP 5: 리포트 생성
    # ──────────────────────────────────────
    phase_start = time.time()
    print("[Phase 5] 분석 리포트 산출물 생성 중...")
    from datetime import datetime
    from utils.xlsx_exporter import export_xlsx

    # reports 폴더 생성
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # 파일명 정의: {대상폴더명}_{시간}
    target_folder_name = os.path.basename(os.path.normpath(abs_target))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{target_folder_name}_{timestamp}"

    report_md_content = format_report(all_findings)

    # 1. 파일 경로 설정
    pdf_output = os.path.join(reports_dir, f"{base_filename}.pdf")
    xlsx_output = os.path.join(reports_dir, f"{base_filename}.xlsx")
    json_output = os.path.join(reports_dir, f"{base_filename}.json")

    # 2. PDF 생성 (내부적으로 HTML 변환 후 PDF 저장)
    exported_pdf_path = export_pdf(report_md_content, pdf_output)

    # 3. XLSX 생성 (상세 취약점 내역)
    exported_xlsx_path = export_xlsx(all_findings, xlsx_output)

    # 4. JSON 생성 (일관성 비교 및 분석용 원본 데이터 백업)
    import json
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)

    total_elapsed = time.time() - pipeline_start

    print(f"\n{'=' * 60}")
    print(f"[+] 분석 완료! (리포트 생성: {_fmt_elapsed(time.time() - phase_start)})")
    print(f"    총 발견된 취약점: {len(all_findings)}개")
    print(f"    총 소요 시간:    {_fmt_elapsed(total_elapsed)}")
    print(f"    - PDF 리포트:  {exported_pdf_path}")
    print(f"    - XLSX 리포트: {exported_xlsx_path}")
    print(f"    - JSON 데이터:  {json_output}")
    print(f"{'=' * 60}")


def main() -> None:
    """CLI 진입점."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Agentic-SAST-Guardian: AI 기반 정적 보안 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python main.py --target ./my_project
  python main.py --target C:\\Users\\dev\\my_project
        """
    )
    parser.add_argument(
        "--target", type=str, required=True,
        help="스캔할 대상 디렉토리 경로"
    )
    args = parser.parse_args()

    run_pipeline(args.target)


if __name__ == "__main__":
    main()
