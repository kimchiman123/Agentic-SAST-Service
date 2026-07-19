# 2차 브랜치 작업 로그

## 목표
- CLI와 로컬 UI가 동일한 서비스 계층을 사용하도록 분리
- 프로젝트 문서·벤치마크·fixture·생성물 구조 정리
- API 키 세션 기본 적용과 명시적 `.env` 저장

## 구현
- `core/pipeline.py`: 단일 실행 lock, RAG 초기화 lock/cache, run-id별 산출물, progress callback
- `core/config.py`: 키 형식 검증, project-root `.env` 고정, atomic replace, portalocker lock
- `ui/app.py`, `run_ui.bat`, `.streamlit/config.toml`: localhost 전용 Streamlit UI
- `main.py`: pipeline service를 호출하는 얇은 CLI 어댑터
- `reports/archive/`: 기존 추적 PDF/XLSX 보존
- `benchmarks/`, `tests/fixtures/`, `docs/{architecture,experiments,plans}/`: 기존 파일 재분류
- RAG benchmark 결과 디렉터리 자동 생성 및 재현용 fixture 경로 연결

## 검증
- `compileall` 통과
- `pytest`: 32 passed, 4 skipped, 18 subtests passed
- Streamlit AppTest smoke test 통과
- Windows portalocker 경로는 pywin32 DLL을 포함한 환경에서 검증

## 사용 방법
- CLI: `python main.py --target <folder>`
- UI: `run_ui.bat` 또는 `python -m streamlit run ui/app.py`
- API 키는 기본적으로 세션 메모리에만 적용되며, 체크박스를 선택할 때만 project-root `.env`에 저장
