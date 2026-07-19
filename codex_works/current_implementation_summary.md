# Agentic-SAST-Guardian 현재 구현 정리

작성 기준: `feat/local-ui-project-structure` 브랜치, 최신 커밋 `e26f4ba`

이 문서는 현재까지 진행한 구현, 보안 설계, 프로젝트 구조 정리, 테스트와 사용 방법을 한곳에 모은 인수인계용 문서입니다.

## 1. 작업 목표

이번 작업의 목표는 기존에 `main.py`에 집중되어 있던 단일 실행 스크립트를 다음과 같은 제품 구조로 확장하는 것이었습니다.

1. Semgrep 결과를 AI가 검증하고 비즈니스 로직까지 분석하는 SAST 파이프라인 유지
2. 파일 접근을 분석 대상 루트 내부로 제한
3. Planner, Executor, Verifier를 분리해 분석 계획과 증거 검증을 명시화
4. CLI와 로컬 UI가 동일한 서비스 계층을 사용하도록 분리
5. API 키를 기본적으로 세션 메모리에만 두고, 명시적으로 선택한 경우에만 로컬 `.env`에 저장
6. 테스트·benchmark·문서·fixture·생성물의 위치를 일관되게 정리

## 2. 브랜치 및 커밋

### 1차 브랜치

- 브랜치: `feat/secure-planned-analysis`
- 커밋: `50bb9ef feat: secure and structure agent analysis`
- 원격 푸시 완료

주요 내용:

- 스캔 루트 경계 정책
- 민감 파일 차단
- Planner → Executor → Verifier 그래프
- 도구·LLM·컨텍스트·finding 예산
- 서버 생성 증거와 SHA-256 검증
- 관련 단위 테스트

### 2차 브랜치

- 브랜치: `feat/local-ui-project-structure`
- 커밋: `e26f4ba feat: add local scan service and UI`
- 원격 푸시 완료

주요 내용:

- CLI/UI 공용 파이프라인 서비스
- localhost 전용 Streamlit UI
- API 키 설정·atomic `.env` 저장
- process-wide 및 cross-process 실행 잠금
- 프로젝트 구조 및 문서·benchmark·fixture 정리
- 기존 리포트 archive 보존

현재 작업 트리는 원격 브랜치와 동기화되어 있으며 커밋되지 않은 변경은 없습니다.

## 3. 최종 프로젝트 구조

```text
Agentic-SAST-Service/
├── main.py                         # 얇은 CLI adapter
├── run_ui.bat                      # localhost Streamlit 실행기
├── scan_project.bat                # CLI 실행기
├── requirements.txt                # 런타임 의존성
├── requirements-dev.txt            # pytest, datasets, ragas
├── .env.example                    # API 키 설정 예시
├── .streamlit/config.toml          # localhost 및 사용량 수집 설정
│
├── core/
│   ├── pipeline.py                 # CLI/UI 공용 분석 서비스
│   ├── config.py                   # API 키 검증·선택적 저장
│   ├── agent.py                    # LangGraph 기반 AI Agent
│   ├── path_policy.py              # 루트·민감 경로 정책
│   ├── scanner.py                  # Semgrep 실행
│   ├── context_builder.py          # 코드 컨텍스트 추출
│   ├── isms_rag.py                 # ISMS-P RAG 지식베이스
│   ├── mcp_tools.py                # read_source/search_code 도구
│   ├── state.py                    # LangGraph 상태 모델
│   └── tools/
│       ├── osv_checker.py          # OSV.dev SCA
│       └── web_search.py            # 제한된 외부 검색
│
├── ui/
│   └── app.py                      # Streamlit UI
├── utils/                          # Markdown/PDF/XLSX exporter
├── tests/
│   ├── unit/                       # 정책·서비스·UI smoke 테스트
│   ├── integration/                # RAG 통합 테스트
│   └── fixtures/                   # 재현 가능한 샘플 프로젝트
├── benchmarks/                     # RAG·Agent consistency 평가
├── docs/
│   ├── architecture/
│   ├── experiments/
│   └── plans/
├── reports/
│   ├── generated/{run-id}/         # 신규 실행 산출물, Git 제외
│   └── archive/                    # 기존 PDF/XLSX 보존본
└── codex_works/                    # 작업 기록
```

## 4. 분석 파이프라인

공용 진입점은 [core/pipeline.py](../core/pipeline.py)의 `run_pipeline()`입니다. CLI의 `main.py`와 Streamlit UI 모두 이 함수를 호출합니다.

### 4.1 대상 경로 검증

`ScanPathPolicy`가 대상 폴더를 실제 경로로 resolve하고 다음을 검사합니다.

- 대상이 존재하는 디렉터리인지 확인
- `..` 상위 경로 이동 차단
- 심볼릭 링크 및 Windows reparse/junction 외부 탈출 차단
- 스캔 루트 외부 절대 경로 차단
- `.env`, `.git`, `.ssh`, `credentials*`, `secrets*`, `id_rsa*` 등 민감 이름 차단
- `vendor`, `node_modules`, `generated`, `reports`, `venv` 등 생성·의존성 디렉터리 차단
- `.pem`, `.key`, `.p12`, `.sqlite` 등 키·인증서·DB 확장자 차단

### 4.2 Tier 1: Semgrep

1. `SemgrepRunner`가 대상 루트에서 정적 분석을 실행합니다.
2. `ContextExtractor`가 finding별 상대 경로, 시작·종료 라인, 코드 컨텍스트를 만듭니다.
3. Discovery Agent가 분석 필요성을 빠르게 판단합니다.
4. Planner Agent가 필요한 파일·라인·확인 항목을 구조화된 `AnalysisPlan`으로 작성합니다.
5. Executor가 승인된 계획 안에서 `read_source`와 `search_code`를 제한적으로 호출합니다.
6. Report 단계가 finding 후보를 생성합니다.
7. Verifier가 실제 파일 증거와 서버 생성 evidence를 확인합니다.

### 4.3 Tier 2: Deep Analysis

Semgrep이 직접 탐지하지 못할 수 있는 인증·인가·결제·세션·파일 처리 등 핵심 로직 파일을 별도로 수집합니다.

- finding이 정확한 `evidence_start_line`/`evidence_end_line`을 반환하도록 구조화
- 서버가 실제 파일에서 증거 스니펫과 SHA-256을 생성
- Verifier가 현재 파일을 다시 읽어 증거를 재구성
- 보고용 `affected_code`가 요약형이어도 서버 증거가 유효한 경우만 승인
- 증거가 없는 자유 형식 finding은 실제 코드 substring 검사를 통과해야 승인

### 4.4 OSV SCA

`scan_dependencies()`가 `package.json` 등 dependency manifest를 먼저 검사하고 OSV.dev 결과를 finding으로 병합합니다. 의존성 finding은 분석 결과의 앞부분에 포함되며 최대 finding 수는 200개로 제한됩니다.

### 4.5 외부 검색

외부 웹 검색은 기본 비활성입니다. opt-in인 경우에도 다음 조건을 만족해야 합니다.

- CVE/CWE ID 또는 길이 3자 이상의 알려진 package token 포함
- 허용된 문자 집합과 길이 제한
- 검색 1회 제한
- 도구 호출 예산 차감
- 로그에는 검색어 원문 대신 길이만 기록

## 5. 예산과 실행 제어

`AnalysisLimits`와 `ScanBudget`이 하나의 스캔 전체에 대해 다음을 관리합니다.

- 최대 worker 수
- 최대 컨텍스트 수
- 최대 tool round 및 tool call 수
- 최대 LLM 호출 수
- 최대 finding 수
- 전체 timeout
- LangGraph recursion limit

추가로 `core/pipeline.py`는 다음 잠금을 사용합니다.

- 같은 프로세스 내 중복 실행 방지: `threading.Lock`
- 여러 프로세스 간 중복 실행 방지: `.runtime/scan.lock`과 `portalocker`
- RAG DB 동시 초기화 방지: `_RAG_LOCK` 및 process 내 knowledge base 재사용

잠금 초기화나 해제 중 예외가 발생해도 process-wide lock이 반드시 해제되도록 outer `try/finally`를 사용합니다.

## 6. API 키 처리

[core/config.py](../core/config.py)는 API 키를 다음과 같이 처리합니다.

- 기본: 현재 UI 세션의 메모리 값으로만 사용
- `OPENAI_API_KEY` 전역 환경변수를 UI 입력으로 덮어쓰지 않음
- `OpenAIAgent(api_key=...)`에 명시적으로 전달
- 공백, 개행, NUL, 제어문자, 허용되지 않은 문자, 길이 위반 거부
- 사용자가 `이 기기에 저장 (.env)`를 선택한 경우에만 저장
- 저장 위치는 앱 프로젝트 루트의 `.env`로 고정
- symlink/reparse point 및 tracked `.env` 저장 거부
- `.env` 원본의 다른 설정은 보존
- `.env.<random>.tmp` 임시 파일 작성 후 atomic `os.replace`
- temp 파일은 Git ignore 대상이며 `.runtime/env.lock`으로 저장 경쟁을 방지
- 오류·로그·보고서에 키 원문을 포함하지 않음

UI는 보안상 localhost(`127.0.0.1`)에만 바인딩하며 XSRF/CORS 보호를 명시적으로 활성화합니다. 원격 배포는 별도 인증·TLS 설계 없이 지원하지 않습니다.

## 7. UI 기능

`ui/app.py`는 다음 흐름을 제공합니다.

1. password 타입 API 키 입력
2. 분석 대상 로컬 폴더 입력
3. `.env` 저장 여부 선택
4. 소스 코드의 OpenAI API 전송 동의
5. 단계별 progress/status 표시
6. finding 수와 severity별 metric 표시
7. PDF/HTML, XLSX, JSON 다운로드

실행 중에는 하나의 분석만 허용합니다. 결과는 `st.session_state`에 보관되며 API 키는 결과 객체나 다운로드 산출물에 포함되지 않습니다.

## 8. 산출물 경로

새 분석은 충돌 방지를 위해 다음 형태로 저장됩니다.

```text
reports/generated/{YYYYMMDD_HHMMSS}_{random}/
├── {target}.pdf 또는 {target}.html
├── {target}.xlsx
└── {target}.json
```

기존 추적 산출물은 삭제하지 않고 다음 위치로 이동했습니다.

```text
reports/archive/
├── EKS_20260426_154728.pdf
├── EKS_20260426_154728.xlsx
├── EKS_20260429_225224.pdf
├── EKS_20260429_225224.xlsx
├── EKS_20260502_121225.pdf
└── EKS_20260502_121225.xlsx
```

## 9. 프로젝트 구조 정리

- `test/`의 재현용 JavaScript fixture를 `tests/fixtures/`로 이동
- RAG 평가 스크립트를 `benchmarks/rag/`로 이동
- Agent consistency 자료를 `benchmarks/agent_consistency/`로 이동
- architecture 문서를 `docs/architecture/`로 이동
- 실험 결과를 `docs/experiments/`로 이동
- 계획 문서를 `docs/plans/`로 이동
- 과거 결과를 `benchmarks/*/baselines/`와 `reports/archive/`로 분리
- 새 benchmark는 결과 디렉터리를 실행 시 자동 생성
- long-context benchmark의 입력을 저장소 내 `tests/fixtures/vuln-test-app`으로 연결
- benchmark 전용 `datasets`, `ragas`를 `requirements-dev.txt`에 추가

## 10. 테스트 및 검증

최종 실행 결과:

```text
32 passed, 4 skipped, 18 subtests passed
```

검증 항목:

- `compileall`: `core`, `ui`, `main.py`, `tests`, `benchmarks`
- 경로 traversal·외부 절대 경로·symlink/junction·민감 파일 차단
- scoped `read_source`/`search_code`
- 예산 및 workflow routing
- 서버 evidence 생성·해시 재검증·변조 거부
- 같은 파일의 다중 finding revision 분리
- revision LLM 실패 시 승인 evidence 보존
- 공용 pipeline의 run-id 산출물
- invalid target 및 중복 scan lock
- API 키 형식·atomic `.env` 저장·symlink env 거부
- Streamlit `AppTest` smoke test
- Windows portalocker 경로는 pywin32 DLL을 포함한 환경에서 검증

4개 skip은 현재 환경의 symlink/junction 생성 권한에 의존하는 테스트입니다.

## 11. 실행 명령

### CLI

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# .env에 OPENAI_API_KEY 설정
python main.py --target C:\path\to\project
```

### UI

```powershell
pip install -r requirements.txt
run_ui.bat
```

또는:

```powershell
python -m streamlit run ui/app.py `
  --server.address=127.0.0.1 `
  --server.enableXsrfProtection=true `
  --server.enableCORS=true `
  --browser.gatherUsageStats=false
```

### 테스트

```powershell
pip install -r requirements-dev.txt
pytest -q
```

## 12. 현재 알려진 운영상 주의사항

- Semgrep 실행에는 Docker Desktop이 필요합니다.
- 첫 RAG 초기화는 문서 파싱·embedding DB 구성으로 시간이 걸릴 수 있습니다.
- UI는 로컬 사용을 전제로 하며 원격 서비스 배포용 인증 계층을 포함하지 않습니다.
- PDF는 `wkhtmltopdf`가 없으면 PyMuPDF 또는 HTML fallback을 사용합니다.
- symlink/junction 테스트는 Windows 권한에 따라 skip될 수 있습니다.
- OpenAI API 호출 비용과 전송되는 코드 컨텍스트 범위를 운영 환경에서 별도 검토해야 합니다.

## 13. 다음 권장 작업

1. 실제 Docker Semgrep과 OpenAI API를 포함한 end-to-end smoke test 추가
2. UI에서 finding 상세 테이블과 파일·라인 필터 추가
3. benchmark 실행을 CI job으로 분리하고 API key가 없는 환경에서는 자동 skip
4. 원격 배포가 필요할 경우 인증, TLS, tenant 격리, secret manager 설계 추가
5. Windows Credential Manager 등 OS secret store를 `.env` fallback보다 우선하는 옵션 검토
