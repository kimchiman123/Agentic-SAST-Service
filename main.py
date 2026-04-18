"""
Agentic-SAST-Guardian 메인 엔트리포인트.
CLI로 타겟 디렉토리를 지정하면 자동으로 정적 분석 → Agent 심층 분석 → 리포트 생성을 수행합니다.
"""
import argparse
import sys
import os
from typing import Any, Dict, List

from dotenv import load_dotenv

from core.scanner import SemgrepRunner
from core.context_builder import ContextExtractor
from core.agent import OpenAIAgent
from core.isms_rag import ISMSKnowledgeBase
from utils.formatter import format_report
from utils.pdf_exporter import export_pdf


def run_pipeline(target_path: str) -> None:
    """보안 분석 파이프라인을 순차적으로 실행합니다."""

    abs_target = os.path.abspath(target_path)
    if not os.path.isdir(abs_target):
        print(f"[!] 오류: 경로가 존재하지 않습니다 -> {abs_target}")
        sys.exit(1)

    print("=" * 60)
    print("  Agentic-SAST-Guardian v1.0")
    print("  AI 기반 정적 보안 분석 도구")
    print("=" * 60)
    print(f"[*] 타겟 디렉토리: {abs_target}\n")

    # ──────────────────────────────────────
    #  STEP 1: Semgrep 정적 분석 (Tier 1)
    # ──────────────────────────────────────
    print("[Phase 1] Semgrep 정적 분석 실행 중...")
    scanner = SemgrepRunner()
    scan_results = scanner.run_scan(abs_target)

    semgrep_contexts: List[Dict[str, Any]] = []
    if scan_results:
        context_builder = ContextExtractor()
        semgrep_contexts = context_builder.extract_contexts(scan_results, abs_target)
        print(f"[+] Semgrep 컨텍스트 {len(semgrep_contexts)}개 추출 완료\n")
    else:
        print("[*] Semgrep에서 탐지된 취약점이 없거나 실행에 실패했습니다.\n")

    # ──────────────────────────────────────
    #  STEP 2: ISMS-P RAG 지식베이스 초기화
    # ──────────────────────────────────────
    print("[Phase 2] ISMS-P 지식베이스 초기화 중...")
    isms_kb = ISMSKnowledgeBase()
    isms_kb.ensure_ready()
    print()

    # ──────────────────────────────────────
    #  STEP 3: 핵심 비즈니스 로직 수집 (Tier 2)
    # ──────────────────────────────────────
    print("[Phase 3] 핵심 비즈니스 로직 파일 수집 중...")
    context_builder = ContextExtractor()
    critical_files = context_builder.extract_critical_files(abs_target)
    print()

    # Semgrep 결과도 없고 핵심 파일도 없으면 종료
    if not semgrep_contexts and not critical_files:
        print("[-] 분석할 대상이 없습니다. 종료합니다.")
        sys.exit(0)

    # ──────────────────────────────────────
    #  STEP 3.5: OSV 외부 의존성 취약점 스캔 (SCA)
    # ──────────────────────────────────────
    import core.tools.osv_checker as osv_checker
    print("[Phase 3.5] OSV.dev 모듈 트리 스캔 및 취약점 조회 중...")
    osv_vulns = osv_checker.scan_dependencies(abs_target)
    if osv_vulns:
        print(f"  [!] 의존성 취약점 내역이 발견되었습니다. Agent 컨텍스트에 주입 중...\n")
    else:
        print("  [+] 알려진 의존성 취약점 없음.\n")

    # ──────────────────────────────────────
    #  STEP 4: Agent 심층 분석 (ISMS-P RAG 연동)
    # ──────────────────────────────────────
    print("[Phase 4] AI Agent 심층 분석 실행 중...")
    agent = OpenAIAgent(isms_kb=isms_kb, osv_vulns=osv_vulns)

    all_findings: List[Dict[str, Any]] = []

    # 3-1: Semgrep 결과 검증 (오탐 필터링 + 재평가)
    if semgrep_contexts:
        print("  [Tier 1] Semgrep 탐지 결과 검증 중...")
        semgrep_findings = agent.analyze_semgrep_findings(semgrep_contexts)
        all_findings.extend(semgrep_findings)
        print(f"  [+] Semgrep 검증 완료: {len(semgrep_findings)}개 실제 취약점 확인\n")

    # 3-2: 핵심 로직 심층 분석 (논리적 취약점 탐지)
    if critical_files:
        print("  [Tier 2] 핵심 비즈니스 로직 심층 분석 중...")
        deep_findings = agent.analyze_critical_logic(critical_files)
        all_findings.extend(deep_findings)
        print(f"  [+] 심층 분석 완료: {len(deep_findings)}개 논리적 취약점 발견\n")

    # ──────────────────────────────────────
    #  STEP 5: 리포트 생성
    # ──────────────────────────────────────
    print("[Phase 5] 분석 리포트 및 메타데이터 산출물 생성 중...")
    from datetime import datetime
    import json
    import csv

    # reports 폴더 생성
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"sast_report_{timestamp}"

    report = format_report(all_findings)

    # 1. 파일 경로 설정
    md_output = os.path.join(reports_dir, f"{base_filename}.md")
    pdf_output = os.path.join(reports_dir, f"{base_filename}.pdf")
    json_output = os.path.join(reports_dir, f"sast_findings_{timestamp}.json")
    csv_output = os.path.join(reports_dir, f"sast_summary_{timestamp}.csv")

    # 2. Markdown 저장
    with open(md_output, "w", encoding="utf-8") as f:
        f.write(report)

    # 3. PDF/HTML 변환
    exported_path = export_pdf(report, pdf_output)

    # 4. 개발자/CI(CD) 인테그레이션용 JSON Raw 데이터 저장
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp, 
            "total_findings": len(all_findings), 
            "findings": all_findings
        }, f, ensure_ascii=False, indent=2)

    # 5. 경영진 대시보드 통계용 CSV 요약 데이터 저장
    with open(csv_output, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["심각도", "취약점 제목", "발생지(파일)", "ISMS-P 위반사항", "취약점 유형코드"])
        for finding in all_findings:
            writer.writerow([
                finding.get("severity", "INFO"),
                finding.get("title", "제목 없음"),
                finding.get("file_path", finding.get("original_file", "")),
                finding.get("isms_p_violation", "해당 없음"),
                finding.get("vulnerability_type", finding.get("rule_id", ""))
            ])

    print(f"\n{'=' * 60}")
    print(f"[+] 분석 완료!")
    print(f"    총 발견된 취약점: {len(all_findings)}개")
    print(f"    - Markdown 리포트:  {md_output}")
    print(f"    - PDF/HTML 리포트:  {exported_path}")
    print(f"    - 전산팀/개발자용(JSON): {json_output}")
    print(f"    - 경영진/통계용(CSV):  {csv_output}")
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
