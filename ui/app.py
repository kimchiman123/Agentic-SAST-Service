"""Agentic-SAST-Guardian 로컬 전용 Streamlit UI."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from core.config import ConfigError, configure_openai_api_key
from core.pipeline import PipelineBusyError, PipelineResult, run_pipeline


st.set_page_config(page_title="Agentic SAST Guardian", layout="wide")
st.title("Agentic SAST Guardian")
st.caption("소스코드는 로컬에서 수집되며, 선택한 코드 컨텍스트가 OpenAI API로 전송됩니다.")


def _download_artifact(label: str, path_value: str, mime: str) -> None:
    path = Path(path_value)
    if path.is_file():
        st.download_button(label, data=path.read_bytes(), file_name=path.name, mime=mime)


def _show_result(result: PipelineResult) -> None:
    st.success(f"분석 완료: {len(result.findings)}개 finding · Run ID {result.run_id}")
    if result.partial:
        st.warning("실행 한도에 도달해 부분 결과가 생성되었습니다.")
    severity_counts: dict[str, int] = {}
    for finding in result.findings:
        severity = str(finding.get("severity", "INFO"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    if severity_counts:
        columns = st.columns(len(severity_counts))
        for column, (severity, count) in zip(columns, sorted(severity_counts.items())):
            column.metric(severity, count)

    first, second, third = st.columns(3)
    with first:
        _download_artifact("PDF/HTML 다운로드", result.artifacts.pdf_or_html, "application/octet-stream")
    with second:
        _download_artifact("XLSX 다운로드", result.artifacts.xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    with third:
        _download_artifact("JSON 다운로드", result.artifacts.json, "application/json")


with st.form("scan_form"):
    api_key = st.text_input(
        "OpenAI API Key",
        type="password",
        help="기본값은 현재 실행 세션에만 보관됩니다.",
    )
    persist_key = st.checkbox(
        "이 기기에 저장 (.env)",
        value=False,
        help="선택한 경우에만 프로젝트 루트의 .env 파일에 저장됩니다.",
    )
    if persist_key:
        st.caption("API 키가 로컬 .env에 평문으로 저장됩니다. 공유 PC에서는 사용하지 마세요.")
    target_path = st.text_input("분석 대상 폴더", placeholder=r"C:\path\to\project")
    consent = st.checkbox("선택한 소스코드 컨텍스트가 OpenAI API로 전송되는 것에 동의합니다.")
    submitted = st.form_submit_button("분석 시작", type="primary")

if submitted:
    if not consent:
        st.error("외부 API 전송 동의가 필요합니다.")
    elif not target_path.strip() or not Path(target_path.strip()).is_dir():
        st.error("존재하는 분석 대상 폴더를 입력하세요.")
    elif not api_key:
        st.error("OpenAI API 키를 입력하세요.")
    else:
        try:
            runtime_api_key = configure_openai_api_key(api_key, persist=persist_key)
            progress_bar = st.progress(0.0)
            status_text = st.empty()

            def on_progress(_phase: str, message: str, progress: float) -> None:
                status_text.info(message)
                progress_bar.progress(progress)

            result = run_pipeline(
                target_path.strip(), progress_callback=on_progress, api_key=runtime_api_key
            )
            st.session_state["last_result"] = result
            status_text.empty()
            _show_result(result)
        except ConfigError as exc:
            st.error(str(exc))
        except PipelineBusyError:
            st.warning("다른 분석이 실행 중입니다. 완료 후 다시 시도하세요.")
        except Exception as exc:
            st.error(f"분석 중 오류가 발생했습니다: {type(exc).__name__}")
elif "last_result" in st.session_state:
    _show_result(st.session_state["last_result"])
