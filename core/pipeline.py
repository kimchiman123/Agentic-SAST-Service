"""Shared, event-driven scan pipeline used by the single local UI."""

from __future__ import annotations

import json
import threading
import time
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import portalocker

from core.agent import AnalysisLimits, OpenAIAgent
from core.batch_analysis import ContextItem, execute_two_passes, pack_contexts
from core.config import RuntimeSettings
from core.context_builder import ContextExtractor
from core.isms_rag import ISMSKnowledgeBase
from core.path_policy import ScanPathPolicy
from core.scanner import SemgrepRunner
from core.state import StageEvent, StageStatus
from core.tools.osv_checker import scan_dependencies
from utils.formatter import format_report
from utils.pdf_exporter import export_pdf
from utils.xlsx_exporter import export_xlsx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "reports" / "generated"
ProgressCallback = Callable[[str, str, float], None]
EventCallback = Callable[[StageEvent], None]
_RAG_LOCK = threading.Lock()
_KNOWLEDGE_BASE: ISMSKnowledgeBase | None = None


class PipelineBusyError(RuntimeError):
    pass


class RunCoordinator:
    """One active scan per process, with a process lock for sibling workers."""

    def __init__(self) -> None:
        self._thread_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self.active_run_id: str | None = None
        self.started_at: float | None = None
        self._process_lock: portalocker.Lock | None = None

    def acquire(self, run_id: str) -> None:
        if not self._thread_lock.acquire(blocking=False):
            raise PipelineBusyError("Another analysis is already running.")
        try:
            # The repository's legacy .runtime may be read-only (for example
            # after archive extraction); a user temp lock still coordinates all
            # local app processes without mutating the scanned project.
            runtime = Path(tempfile.gettempdir()) / "agentic-sast-runtime"
            runtime.mkdir(exist_ok=True)
            lock = portalocker.Lock(str(runtime / "scan.lock"), mode="a", timeout=0, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
            try:
                lock.acquire()
            except portalocker.exceptions.LockException as exc:
                raise PipelineBusyError("Another analysis is already running.") from exc
            with self._state_lock:
                self.active_run_id = run_id
                self.started_at = time.monotonic()
                self._process_lock = lock
        except Exception:
            self._thread_lock.release()
            raise

    def release(self) -> None:
        with self._state_lock:
            lock, self._process_lock = self._process_lock, None
            self.active_run_id = None
            self.started_at = None
        try:
            if lock is not None:
                lock.release()
        finally:
            if self._thread_lock.locked():
                self._thread_lock.release()


_RUN_COORDINATOR = RunCoordinator()
# Kept as a compatibility seam for existing callers and regression tests.
_SCAN_LOCK = _RUN_COORDINATOR._thread_lock


@dataclass(frozen=True)
class ReportArtifacts:
    pdf_or_html: str = ""
    xlsx: str = ""
    json: str = ""
    files: Dict[str, bytes] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class PipelineResult:
    run_id: str
    target_path: str
    findings: List[Dict[str, Any]]
    artifacts: ReportArtifacts
    elapsed_seconds: float
    partial: bool = False
    warnings: List[str] = field(default_factory=list)
    semgrep_findings: List[Dict[str, Any]] = field(default_factory=list)
    agent_analyses: List[Dict[str, Any]] = field(default_factory=list)
    verification_results: List[Dict[str, Any]] = field(default_factory=list)
    approved_findings: List[Dict[str, Any]] = field(default_factory=list)
    request_stats: Dict[str, int] = field(default_factory=dict)
    stage_events: List[StageEvent] = field(default_factory=list)


def _osv_findings(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{
        "source": "osv", "is_true_positive": True, "severity": "HIGH",
        "title": f"Vulnerable dependency: {item.get('package', 'unknown')}",
        "description": item.get("summary", "Known dependency vulnerability."),
        "vulnerability_type": "Supply Chain", "file_path": "package.json",
        "affected_code": f"{item.get('package', '')}@{item.get('version', '')}",
        "remediation_description": "Upgrade to the vendor-recommended fixed version.",
        "decision_tree": ["Inspect manifest", "Check vulnerability ID", str(item.get("cve_id", ""))],
    } for item in vulnerabilities]


def _artifact_bytes(path: str, limit: int) -> bytes:
    candidate = Path(path)
    if not candidate.is_file() or candidate.stat().st_size > limit:
        return b""
    return candidate.read_bytes()


def run_pipeline(
    target_path: str,
    *,
    progress_callback: Optional[ProgressCallback] = None,
    event_callback: Optional[EventCallback] = None,
    output_root: Optional[Path] = None,
    api_key: Optional[str] = None,
    settings: Optional[RuntimeSettings] = None,
) -> PipelineResult:
    """Run Semgrep, batched LLM analysis, verification, and reporting once."""
    runtime = settings or RuntimeSettings.from_env()
    if api_key is not None:
        runtime = runtime.with_api_key(api_key)
    run_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    events: list[StageEvent] = []
    started_at = time.monotonic()

    def emit(stage: str, status: StageStatus, message: str, current: int = 0, total: int = 0, *, error_code: str | None = None, payload: Dict[str, Any] | None = None) -> None:
        event = StageEvent(run_id, stage, status, current, total, message, error_code, payload or {})  # type: ignore[arg-type]
        events.append(event)
        if event_callback:
            event_callback(event)
        if progress_callback:
            phase_progress = {"semgrep": 0.15, "agent": 0.55, "verification": 0.78, "report": 1.0}[stage]
            legacy_phase = "complete" if stage == "report" and status == "completed" else stage
            progress_callback(legacy_phase, message, phase_progress if status != "running" else min(phase_progress, 0.9))

    _RUN_COORDINATOR.acquire(run_id)
    try:
        policy = ScanPathPolicy(target_path)
        safe_target = policy.root
        root = (output_root or DEFAULT_OUTPUT_ROOT).resolve()
        run_directory = root / run_id
        run_directory.mkdir(parents=True, exist_ok=False)

        emit("semgrep", "running", "정적 분석을 실행하고 있습니다.", 0, 1)
        scan_results = SemgrepRunner(policy).run_scan(str(safe_target))
        if scan_results is None:
            emit("semgrep", "failed", "정적 분석을 완료하지 못했습니다.", 1, 1, error_code="semgrep_failed")
            emit("agent", "skipped", "정적 분석 실패로 AI 분석을 건너뛰었습니다.")
            emit("verification", "skipped", "정적 분석 실패로 검증을 건너뛰었습니다.")
            emit("report", "skipped", "정적 분석 실패로 보고서 생성을 건너뛰었습니다.")
            return PipelineResult(run_id, str(safe_target), [], ReportArtifacts(), time.monotonic() - started_at, True, ["semgrep_failed"], stage_events=events)

        raw_semgrep = list(scan_results.get("results", []))[:runtime.max_semgrep_findings]
        # Keep the scanner's normalized JSON snapshot without constructing a
        # second runner (important for injected/test scanner implementations).
        snapshot_limit = 20 * 1024 * 1024
        snapshot_size = 2
        semgrep_findings: list[dict[str, Any]] = []
        snapshot_truncated = False
        for item in raw_semgrep:
            if not isinstance(item, dict):
                continue
            encoded = json.dumps(item, ensure_ascii=False, default=str).encode("utf-8")
            if snapshot_size + len(encoded) > snapshot_limit:
                snapshot_truncated = True
                break
            semgrep_findings.append(dict(item))
            snapshot_size += len(encoded)
        emit("semgrep", "completed", "정적 분석을 완료했습니다.", 1, 1, payload={"finding_count": len(raw_semgrep)})

        context_builder = ContextExtractor(policy)
        semgrep_contexts = context_builder.extract_contexts({"results": raw_semgrep}, str(safe_target)) if raw_semgrep else []
        # Critical business logic must be inspected even if Semgrep returns no
        # findings; otherwise a valid NVIDIA key is never used for clean scans.
        critical_contexts = context_builder.extract_critical_files(str(safe_target))
        osv_vulnerabilities = scan_dependencies(str(safe_target), policy)
        all_findings: list[dict[str, Any]] = _osv_findings(osv_vulnerabilities)
        agent_analyses: list[dict[str, Any]] = []
        verification_results: list[dict[str, Any]] = []
        approved_findings: list[dict[str, Any]] = []
        request_stats = {"analysis": 0, "verification": 0}
        warnings: list[str] = []
        if snapshot_truncated:
            warnings.append("semgrep_snapshot_truncated")
        partial = False

        contexts = [*semgrep_contexts, *critical_contexts]
        # Stable IDs are assigned before selection; preserve input order for equal priority.
        selected = [ContextItem.from_payload(context) for context in contexts][:50]
        if not selected:
            emit("agent", "skipped", "AI 분석 대상 코드를 찾지 못했습니다.")
            emit("verification", "skipped", "AI 분석 대상이 없어 검증을 건너뛰었습니다.")
        elif not runtime.api_key:
            partial = True
            warnings.append("api_key_missing")
            emit("agent", "failed", "AI 분석에 사용할 API 키가 필요합니다.", error_code="api_key_missing")
            emit("verification", "skipped", "AI 분석 실패로 검증을 건너뛰었습니다.")
        else:
            global _KNOWLEDGE_BASE
            with _RAG_LOCK:
                if _KNOWLEDGE_BASE is None:
                    knowledge_base = ISMSKnowledgeBase()
                    knowledge_base.ensure_ready()
                    _KNOWLEDGE_BASE = knowledge_base
                knowledge_base = _KNOWLEDGE_BASE
            batches = pack_contexts(
                selected, envelope={"project": safe_target.name}, limits=runtime.batch,
                context_window_tokens=runtime.nvidia_context_window_tokens,
            )
            emit("agent", "running", "AI 분석 대상을 묶어 분석하고 있습니다.", 0, len(selected), payload={"batch_count": len(batches)})
            limits = AnalysisLimits(max_llm_calls=runtime.max_llm_requests)
            agent = OpenAIAgent(
                isms_kb=knowledge_base, osv_vulns=osv_vulnerabilities,
                target_root=str(safe_target), api_key=runtime.api_key,
                limits=limits, model=runtime.model,
                context_window_tokens=runtime.nvidia_context_window_tokens,
            )
            batch_adapter = getattr(agent, "run_batch_pass", None)
            if callable(batch_adapter):
                analyses, verifications = execute_two_passes(batches, batch_adapter, request_budget=runtime.max_llm_requests)
            else:
                # Compatibility with legacy test doubles and third-party agent adapters.
                legacy_findings: list[dict[str, Any]] = []
                if semgrep_contexts and hasattr(agent, "analyze_semgrep_findings"):
                    legacy_findings.extend(agent.analyze_semgrep_findings(semgrep_contexts))
                if critical_contexts and hasattr(agent, "analyze_critical_logic"):
                    legacy_findings.extend(agent.analyze_critical_logic(critical_contexts))
                agent_analyses.extend({"context_id": item.context_id, "findings": legacy_findings} for item in selected)
                analyses, verifications = [], []
            request_stats["analysis"] = sum(item.request_count for item in analyses)
            request_stats["verification"] = sum(item.request_count for item in verifications)
            for outcome in analyses:
                if outcome.status == "completed":
                    agent_analyses.extend(dict(item) for item in outcome.results)
                else:
                    warnings.extend(outcome.errors)
            agent_status: StageStatus = "completed" if (
                all(item.status == "completed" for item in analyses)
                and all(item.get("status") == "ok" for item in agent_analyses)
            ) else "partial"
            partial = partial or agent_status == "partial"
            emit("agent", agent_status, "AI 분석을 완료했습니다.", len(agent_analyses), len(selected), payload={"batch_count": len(batches), "request_count": request_stats["analysis"]})

            emit("verification", "running", "AI 분석 결과를 검증하고 있습니다.", 0, len(agent_analyses))
            analysis_by_id = {str(item["context_id"]): item for item in agent_analyses}
            for outcome in verifications:
                if outcome.status == "completed":
                    verification_results.extend(dict(item) for item in outcome.results)
                else:
                    warnings.extend(outcome.errors)
            for result in verification_results:
                if result.get("verdict") == "tp":
                    analysis = analysis_by_id.get(str(result.get("context_id")), {})
                    for finding in analysis.get("findings", []):
                        if isinstance(finding, dict):
                            approved_findings.append(dict(finding, context_id=result["context_id"]))
            verification_status: StageStatus = "completed" if (
                len(verification_results) == len(agent_analyses)
                and all(item.get("status") == "ok" for item in verification_results)
            ) else "partial"
            partial = partial or verification_status == "partial"
            emit("verification", verification_status, "AI 분석 결과 검증을 완료했습니다.", len(verification_results), len(agent_analyses), payload={"request_count": request_stats["verification"]})
            all_findings.extend(approved_findings)

        emit("report", "running", "보고서 파일을 생성하고 있습니다.", 0, 1)
        try:
            report_content = format_report(all_findings[:200])
            base_name = safe_target.name or "scan"
            pdf_path = export_pdf(report_content, str(run_directory / f"{base_name}.pdf"))
            xlsx_path = export_xlsx(all_findings[:200], str(run_directory / f"{base_name}.xlsx"))
            json_path = run_directory / f"{base_name}.json"
            json_path.write_text(json.dumps(all_findings[:200], indent=2, ensure_ascii=False), encoding="utf-8")
            artifact_files: dict[str, bytes] = {}
            remaining_artifact_bytes = 50 * 1024 * 1024
            for name, path in (("pdf_or_html", str(pdf_path)), ("xlsx", str(xlsx_path)), ("json", str(json_path))):
                data = _artifact_bytes(path, remaining_artifact_bytes)
                artifact_files[name] = data
                remaining_artifact_bytes -= len(data)
                if not data and Path(path).is_file() and Path(path).stat().st_size:
                    warnings.append("artifact_bytes_not_retained")
            artifacts = ReportArtifacts(str(Path(pdf_path).resolve()), str(Path(xlsx_path).resolve()), str(json_path.resolve()), artifact_files)
        except Exception as exc:
            partial = True
            warnings.append("report_failed")
            emit("report", "failed", "보고서 생성에 실패했지만 단계 결과는 보존했습니다.", 1, 1, error_code=type(exc).__name__)
            return PipelineResult(run_id, str(safe_target), all_findings[:200], ReportArtifacts(), time.monotonic() - started_at, partial, warnings, semgrep_findings, agent_analyses, verification_results, approved_findings, request_stats, events)
        emit("report", "completed", "보고서 파일을 준비했습니다.", 1, 1, payload={"finding_count": len(all_findings)})
        return PipelineResult(run_id, str(safe_target), all_findings[:200], artifacts, time.monotonic() - started_at, partial, warnings, semgrep_findings, agent_analyses, verification_results, approved_findings, request_stats, events)
    except PipelineBusyError:
        raise
    except Exception as exc:
        # Public callback/error surfaces intentionally use a type, never secrets/source text.
        emit("report", "failed", "분석이 예기치 않게 중단되었습니다.", error_code=type(exc).__name__)
        raise
    finally:
        _RUN_COORDINATOR.release()
