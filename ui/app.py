"""Streamlit rendering for the single local Agentic SAST entrypoint."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from core.config import ConfigError, RuntimeSettings
from core.pipeline import PipelineBusyError, PipelineResult, run_pipeline
from core.state import StageEvent
from core.upload_workspace import UploadedFile, UploadWorkspace, UploadWorkspaceError, validate_local_directory


_STAGES = (
    ("semgrep", "1. Semgrep"),
    ("agent", "2. AI 분석"),
    ("verification", "3. 결과 검증"),
    ("report", "4. 보고서 생성"),
)


def _download_artifact(label: str, data: bytes, fallback_path: str, mime: str, *, retained: bool) -> None:
    if not data and fallback_path and not retained:
        path = Path(fallback_path)
        if path.is_file() and path.stat().st_size <= 50 * 1024 * 1024:
            data = path.read_bytes()
    if data:
        st.download_button(label, data=data, file_name=Path(fallback_path or label).name, mime=mime)
    elif retained:
        st.caption(f"{label} 파일이 세션에 보관할 수 있는 크기를 초과했습니다.")


def _show_result(result: PipelineResult) -> None:
    st.success(f"분석 완료: {len(result.findings)}건의 결과를 확인했습니다. (실행 ID: {result.run_id})")
    if result.partial:
        st.warning("일부 단계가 완전히 끝나지 않았습니다. 아래 단계별 상태를 확인하세요.")
    if result.warnings:
        st.caption("주의: " + ", ".join(sorted(set(result.warnings))))
    verdict_counts: dict[str, int] = {}
    for item in result.verification_results:
        verdict = str(item.get("verdict", "unknown"))
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    if verdict_counts:
        for column, (verdict, count) in zip(st.columns(len(verdict_counts)), sorted(verdict_counts.items())):
            column.metric(verdict.upper(), count)
    if result.findings:
        st.dataframe(result.findings, use_container_width=True, hide_index=True)

    first, second, third = st.columns(3)
    with first:
        _download_artifact("PDF/HTML 다운로드", result.artifacts.files.get("pdf_or_html", b""), result.artifacts.pdf_or_html, "application/octet-stream", retained="pdf_or_html" in result.artifacts.files)
    with second:
        _download_artifact("XLSX 다운로드", result.artifacts.files.get("xlsx", b""), result.artifacts.xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", retained="xlsx" in result.artifacts.files)
    with third:
        _download_artifact("JSON 다운로드", result.artifacts.files.get("json", b""), result.artifacts.json, "application/json", retained="json" in result.artifacts.files)


def _stage_details(state: dict[str, Any]) -> list[str]:
    """Return only count-based, source/key-free details for a stage card."""
    details: list[str] = []
    current, total = int(state.get("current", 0)), int(state.get("total", 0))
    if total:
        details.append(f"처리 진행: {current}/{total}건")
    payload = state.get("payload", {})
    if not isinstance(payload, dict):
        return details
    labels = {
        "finding_count": "탐지 결과",
        "batch_count": "분석 묶음",
        "request_count": "LLM 요청",
    }
    for key, label in labels.items():
        value = payload.get(key)
        if isinstance(value, int) and value >= 0:
            details.append(f"{label}: {value}건")
    return details


def _render_stage_rows() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    rows: dict[str, Any] = {}
    state: dict[str, dict[str, Any]] = {}
    for stage, label in _STAGES:
        container = st.container(border=True)
        container.subheader(label)
        rows[stage] = container.empty()
        rows[stage].caption("대기 중")
        state[stage] = {"status": "pending", "message": "대기 중", "current": 0, "total": 0, "payload": {}}
    return rows, state


def _render_stage(row: Any, state: dict[str, Any]) -> None:
    status = state["status"]
    message = state["message"]
    with row.container():
        if status == "failed":
            st.error(message)
        elif status == "partial":
            st.warning(message)
        elif status == "completed":
            st.success(message)
        else:
            st.info(message)
        for detail in _stage_details(state):
            st.markdown(f"- {detail}")


def render_app() -> None:
    """Render without import-time side effects; called only by the child entrypoint."""
    st.set_page_config(page_title="Agentic SAST Guardian", layout="wide")
    if st.session_state.pop("clear_api_key_after_run", False):
        # Clear before this widget is instantiated. Streamlit forbids changing
        # a widget-backed key after creation in the same rerun.
        st.session_state.pop("api_key", None)
    st.title("Agentic SAST Guardian")
    st.caption("로컬 소스 코드 분석 도구입니다. UI에 입력한 API 키는 이번 실행에만 사용되며 파일에 저장하지 않습니다.")
    running = bool(st.session_state.get("scan_running", False))

    # Widgets are deliberately outside a form so changing the input mode or
    # selected upload applies immediately on Streamlit's normal rerun.
    input_mode = st.radio("분석 대상 입력 방식", ("로컬 경로", "파일 업로드"), disabled=running, horizontal=True)
    api_key = st.text_input("OpenAI 또는 NVIDIA API 키 (환경 변수에 있으면 선택 사항)", type="password", key="api_key", disabled=running)
    target_path = ""
    uploaded: list[Any] = []
    if input_mode == "로컬 경로":
        target_path = st.text_input("프로젝트 디렉터리", placeholder=r"C:\path\to\project", disabled=running)
    else:
        uploaded = st.file_uploader("ZIP 프로젝트 1개 또는 소스 파일 여러 개", accept_multiple_files=True, disabled=running)
    consent = st.checkbox("선택한 코드 문맥을 설정된 LLM 제공자에게 전송하는 것에 동의합니다.", disabled=running)
    submitted = st.button("분석 시작", type="primary", disabled=running)

    rows, stage_state = _render_stage_rows()
    if not submitted and "last_result" in st.session_state:
        for event in st.session_state["last_result"].stage_events:
            stage_state[event.stage] = {
                "status": event.status,
                "message": event.message or event.status.title(),
                "current": event.current,
                "total": event.total,
                "payload": event.payload,
            }
            _render_stage(rows[event.stage], stage_state[event.stage])
    if submitted:
        if not consent:
            st.error("LLM 제공자에게 코드 문맥을 전송하려면 동의가 필요합니다.")
            return
        st.session_state["scan_running"] = True

        def on_event(event: StageEvent) -> None:
            stage_state[event.stage] = {
                "status": event.status,
                "message": event.message or event.status.title(),
                "current": event.current,
                "total": event.total,
                "payload": event.payload,
            }
            _render_stage(rows[event.stage], stage_state[event.stage])

        try:
            settings = RuntimeSettings.from_env()
            if api_key:
                settings = settings.with_api_key(api_key)
            if input_mode == "로컬 경로":
                if not target_path.strip():
                    raise UploadWorkspaceError("프로젝트 디렉터리를 입력하세요.")
                safe_target = validate_local_directory(target_path.strip())
                result = run_pipeline(str(safe_target), settings=settings, event_callback=on_event)
            else:
                if not uploaded:
                    raise UploadWorkspaceError("ZIP 프로젝트 또는 소스 파일을 하나 이상 업로드하세요.")
                uploaded_files = [UploadedFile(item.name, item.getvalue()) for item in uploaded]
                zip_files = [item for item in uploaded_files if item.name.casefold().endswith(".zip")]
                if zip_files and (len(zip_files) != 1 or len(uploaded_files) != 1):
                    raise UploadWorkspaceError("ZIP 파일은 하나만 업로드하거나, ZIP 없이 소스 파일만 업로드하세요.")
                with UploadWorkspace.create() as workspace:
                    safe_target = workspace.extract_zip(zip_files[0].data, settings.upload) if zip_files else workspace.write_loose_files(uploaded_files, settings.upload)
                    result = run_pipeline(str(safe_target), settings=settings, event_callback=on_event)
            st.session_state["last_result"] = result
            _show_result(result)
        except (ConfigError, UploadWorkspaceError) as exc:
            st.error(str(exc))
        except PipelineBusyError:
            st.warning("이 프로세스에서 다른 분석이 이미 실행 중입니다.")
        except Exception as exc:
            st.error(f"분석이 안전하게 중단되었습니다: {type(exc).__name__}")
        finally:
            st.session_state["scan_running"] = False
            st.session_state["clear_api_key_after_run"] = True
            st.rerun()
    elif "last_result" in st.session_state:
        _show_result(st.session_state["last_result"])


if __name__ == "__main__":
    render_app()
