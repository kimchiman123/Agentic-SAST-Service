"""Smoke test for the import-safe Streamlit UI."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_local_ui_renders_required_controls() -> None:
    app_path = Path(__file__).resolve().parents[2] / "ui" / "app.py"
    app = AppTest.from_file(str(app_path)).run(timeout=30)

    assert not app.exception
    assert [item.label for item in app.text_input] == [
        "OpenAI 또는 NVIDIA API 키 (환경 변수에 있으면 선택 사항)",
        "프로젝트 디렉터리",
    ]
    assert [item.label for item in app.checkbox] == [
        "선택한 코드 문맥을 설정된 LLM 제공자에게 전송하는 것에 동의합니다.",
    ]
    assert [item.label for item in app.button] == ["분석 시작"]
