"""Streamlit UI가 외부 호출 없이 렌더링되는지 확인합니다."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_local_ui_renders_required_controls() -> None:
    app_path = Path(__file__).resolve().parents[2] / "ui" / "app.py"
    app = AppTest.from_file(str(app_path)).run(timeout=30)

    assert not app.exception
    assert [item.label for item in app.text_input] == ["OpenAI API Key", "분석 대상 폴더"]
    assert [item.label for item in app.checkbox] == [
        "이 기기에 저장 (.env)",
        "선택한 소스코드 컨텍스트가 OpenAI API로 전송되는 것에 동의합니다.",
    ]
    assert [item.label for item in app.button] == ["분석 시작"]
