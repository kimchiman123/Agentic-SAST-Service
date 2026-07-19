"""CLI와 로컬 UI가 공유하는 스캔 파이프라인 서비스."""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import portalocker

from core.agent import OpenAIAgent
from core.context_builder import ContextExtractor
from core.isms_rag import ISMSKnowledgeBase
from core.path_policy import ScanPathPolicy
from core.scanner import SemgrepRunner
from core.tools.osv_checker import scan_dependencies
from utils.formatter import format_report
from utils.pdf_exporter import export_pdf
from utils.xlsx_exporter import export_xlsx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "reports" / "generated"
ProgressCallback = Callable[[str, str, float], None]
_SCAN_LOCK = threading.Lock()
_RAG_LOCK = threading.Lock()
_KNOWLEDGE_BASE: ISMSKnowledgeBase | None = None


class PipelineBusyError(RuntimeError):
    """동일 프로세스에서 이미 스캔이 실행 중일 때 발생합니다."""


@dataclass(frozen=True)
class ReportArtifacts:
    pdf_or_html: str
    xlsx: str
    json: str


@dataclass(frozen=True)
class PipelineResult:
    run_id: str
    target_path: str
    findings: List[Dict[str, Any]]
    artifacts: ReportArtifacts
    elapsed_seconds: float
    partial: bool = False
    warnings: List[str] = field(default_factory=list)


def _notify(callback: Optional[ProgressCallback], phase: str, message: str, progress: float) -> None:
    if callback:
        callback(phase, message, min(1.0, max(0.0, progress)))


def _osv_findings(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{
        "source": "osv",
        "is_true_positive": True,
        "severity": "HIGH",
        "title": f"취약한 의존성: {item.get('package', 'unknown')}",
        "description": item.get("summary", "OSV에서 알려진 취약점이 확인되었습니다."),
        "vulnerability_type": "Supply Chain",
        "file_path": "package.json",
        "affected_code": f"{item.get('package', '')}@{item.get('version', '')}",
        "remediation_description": "OSV 권고 버전 또는 최신 안전 버전으로 업데이트하세요.",
        "decision_tree": ["의존성 manifest 확인", "OSV 취약점 ID 확인", str(item.get("cve_id", ""))],
    } for item in vulnerabilities]


def run_pipeline(
    target_path: str,
    *,
    progress_callback: Optional[ProgressCallback] = None,
    output_root: Optional[Path] = None,
    api_key: Optional[str] = None,
) -> PipelineResult:
    """단일 스캔을 실행하고 구조화된 결과와 run-id별 산출물을 반환합니다."""
    if not _SCAN_LOCK.acquire(blocking=False):
        raise PipelineBusyError("다른 분석이 실행 중입니다.")

    process_lock = None
    try:
        runtime_directory = PROJECT_ROOT / ".runtime"
        runtime_directory.mkdir(exist_ok=True)
        process_lock = portalocker.Lock(
            str(runtime_directory / "scan.lock"), mode="a", timeout=0,
            flags=portalocker.LOCK_EX | portalocker.LOCK_NB,
        )
        try:
            process_lock.acquire()
        except portalocker.exceptions.LockException as exc:
            raise PipelineBusyError("다른 분석이 실행 중입니다.") from exc

        started_at = time.monotonic()
        policy = ScanPathPolicy(target_path)
        safe_target = policy.root
        run_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        root = (output_root or DEFAULT_OUTPUT_ROOT).resolve()
        run_directory = root / run_id
        run_directory.mkdir(parents=True, exist_ok=False)

        _notify(progress_callback, "semgrep", "정적 분석을 실행합니다.", 0.08)
        scan_results = SemgrepRunner(policy).run_scan(str(safe_target))
        context_builder = ContextExtractor(policy)
        semgrep_contexts = context_builder.extract_contexts(scan_results, str(safe_target)) if scan_results else []

        _notify(progress_callback, "rag", "ISMS-P 지식베이스를 준비합니다.", 0.24)
        global _KNOWLEDGE_BASE
        with _RAG_LOCK:
            if _KNOWLEDGE_BASE is None:
                knowledge_base = ISMSKnowledgeBase()
                knowledge_base.ensure_ready()
                _KNOWLEDGE_BASE = knowledge_base
            knowledge_base = _KNOWLEDGE_BASE

        _notify(progress_callback, "context", "핵심 비즈니스 로직을 수집합니다.", 0.38)
        critical_files = context_builder.extract_critical_files(str(safe_target))

        _notify(progress_callback, "osv", "의존성 취약점을 확인합니다.", 0.48)
        osv_vulnerabilities = scan_dependencies(str(safe_target), policy)
        all_findings = _osv_findings(osv_vulnerabilities)

        partial = False
        warnings: List[str] = []
        if semgrep_contexts or critical_files:
            _notify(progress_callback, "agent", "계획 기반 AI 분석을 실행합니다.", 0.58)
            agent = OpenAIAgent(
                isms_kb=knowledge_base,
                osv_vulns=osv_vulnerabilities,
                target_root=str(safe_target),
                api_key=api_key,
            )
            if semgrep_contexts:
                all_findings.extend(agent.analyze_semgrep_findings(semgrep_contexts))
            if critical_files:
                all_findings.extend(agent.analyze_critical_logic(critical_files))
            budget_stop_reason = agent.budget.stop_reason()
            if budget_stop_reason:
                partial = True
                warnings.append(budget_stop_reason)

        all_findings = all_findings[:200]
        _notify(progress_callback, "report", "보고서를 생성합니다.", 0.9)
        report_content = format_report(all_findings)
        base_name = safe_target.name or "scan"
        pdf_path = export_pdf(report_content, str(run_directory / f"{base_name}.pdf"))
        xlsx_path = export_xlsx(all_findings, str(run_directory / f"{base_name}.xlsx"))
        json_path = run_directory / f"{base_name}.json"
        json_path.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False), encoding="utf-8")

        _notify(progress_callback, "complete", "분석이 완료되었습니다.", 1.0)
        return PipelineResult(
            run_id=run_id,
            target_path=str(safe_target),
            findings=all_findings,
            artifacts=ReportArtifacts(
                pdf_or_html=str(Path(pdf_path).resolve()),
                xlsx=str(Path(xlsx_path).resolve()),
                json=str(json_path.resolve()),
            ),
            elapsed_seconds=time.monotonic() - started_at,
            partial=partial,
            warnings=warnings,
        )
    finally:
        try:
            if process_lock is not None:
                process_lock.release()
        finally:
            _SCAN_LOCK.release()
