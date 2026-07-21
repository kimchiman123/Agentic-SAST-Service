from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_ui_defaults_to_local_path_and_shows_all_pipeline_stages() -> None:
    app_path = Path(__file__).resolve().parents[2] / "ui" / "app.py"
    assert 'input_mode == "Local path"' not in app_path.read_text(encoding="utf-8")
    app = AppTest.from_file(str(app_path)).run(timeout=30)

    assert not app.exception
    assert app.radio[0].value == "로컬 경로"
    assert [heading.value for heading in app.subheader] == [
        "1. Semgrep", "2. AI 분석", "3. 결과 검증", "4. 보고서 생성",
    ]
    app.radio[0].set_value("파일 업로드").run(timeout=30)
    assert not app.exception
    assert app.file_uploader[0].label == "ZIP 프로젝트 1개 또는 소스 파일 여러 개"
