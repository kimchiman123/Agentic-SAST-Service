# 오픈소스 UX 및 Agent 제어 개선 계획

작성일: 2026-07-19

## 작업 목표

- 비전문 사용자도 로컬 UI에서 API 키와 분석 경로를 설정하고 스캔한다.
- LLM 분석을 구조화된 계획, 제한된 실행, 독립 근거 검증으로 분리한다.
- 분석 대상 밖 파일 및 민감정보가 모델·Semgrep·OSV로 전달되지 않게 한다.
- 테스트, 벤치마크, 문서, 생성 산출물의 위치를 분리한다.

## What already exists

- `main.py`: CLI와 전체 분석 파이프라인. UI도 이 흐름을 서비스 함수로 재사용한다.
- `core/agent.py`: Discovery, ToolNode, Reporter, 웹 검색 흐름. 구조를 유지하며 Planner와 Verifier를 삽입한다.
- `core/context_builder.py`: Semgrep 문맥과 중요 파일 수집. 공통 경로 정책을 적용한다.
- `core/mcp_tools.py`: `read_source`, `search_code`. target-root bound factory로 교체한다.
- `python-dotenv`: 환경변수 로드가 이미 존재한다. 선택적 저장에도 `set_key`를 사용한다.
- `reports/`, `test/`, `docs/`: 필요한 자료는 존재하지만 목적별 분리가 필요하다.

## 결정된 아키텍처

```text
사용자/CLI
   |
   v
Pipeline Service -----> ScanPathPolicy
   |                      |-- root containment
   |                      |-- symlink/reparse 차단
   |                      `-- secret/vendor/generated 제외
   |
   +--> Semgrep / ContextExtractor / OSV / MCP tools
   |
   `--> Discovery
          |
          v
       Planner (structured, no tools)
          |
          v
       Policy Gate
          |
          v
       Executor <--> root-scoped tools (최대 3 rounds)
          |
          v
       Synthesizer
          |
          v
       Evidence Verifier
          | reject
          +------> Revision (최대 1회)
          |
          v
       Reporter --> reports/generated/<run-id>/
```

Planner는 숨은 CoT를 요구하지 않는다. 가설, 필요한 증거, 검사 항목, 중단 조건만 구조화한다. Verifier는 실제 상대경로·라인·근거가 없는 finding을 제거한다.

## 브랜치 전략

1. `feat/secure-planned-analysis`
   - 공통 `ScanPathPolicy`
   - Semgrep, ContextExtractor, OSV, MCP 경로 격리
   - `Planner -> Policy Gate -> Executor -> Verifier -> Reporter`
   - 컨텍스트별·스캔 전체 예산
   - OSV 조기 종료 결함 수정
   - 보안·graph·회귀 테스트
2. `feat/local-ui-project-structure`
   - 재사용 가능한 pipeline service와 `PipelineResult`
   - localhost-only Streamlit UI
   - API 키 session-only 기본, 명시적 `.env` 저장
   - 단일 스캔 lock, run-id 출력 격리, RAG 초기화 lock
   - 파일구조 이동과 문서 갱신

## 파일구조 목표

```text
app.py
core/
tests/
  unit/
  integration/
  fixtures/
benchmarks/
  rag/
  agent_consistency/
docs/
  experiments/
  plans/
reports/
  generated/          # gitignored
codex_works/
```

## 제어 예산

- 기본 worker: 2
- 컨텍스트별 tool round: 3
- verifier revision: 1
- graph recursion limit: 명시적 고정
- 스캔 전체 후보·LLM 호출·도구 호출·finding·실행시간 상한
- 상한 도달 시 실패로 위장하지 않고 부분 결과와 중단 사유 반환

## 테스트 계획

```text
ScanPathPolicy
|-- 정상 상대경로 허용
|-- ../ 및 외부 절대경로 차단
|-- symlink/junction/reparse 탈출 차단
|-- .env, key, cert, .git, vendor, generated 차단
`-- ContextExtractor/OSV/Semgrep/MCP 동일 정책 확인

Agent graph
|-- Discovery false -> Planner 미호출
|-- Planner 실패 -> 보수적 fallback
|-- 유효 plan 없이 Executor 미호출
|-- tool/global budget에서 정상 종료
|-- 근거 없는 finding verifier 기각
|-- revision 최대 1회
`-- 기존 finding JSON schema 호환

UI/service
|-- session-only key는 디스크 미기록
|-- opt-in 저장 시 기존 env 보존·키 비노출
|-- CR/LF/NUL, symlink env 파일 거부
|-- invalid target과 scan failure 복구 메시지
|-- 동시 실행 거부
|-- run-id별 결과 다운로드
`-- 기존 CLI 호출 호환

Evaluation
|-- run-id로 결과 선택
|-- Precision/Recall/F1 유지
|-- 파일·라인 evidence 충족률
|-- verifier 기각률
`-- plan/evidence 재현성
```

## 실패 모드

- 분석 대상 코드의 prompt injection: 공통 경로 정책과 read-only tool budget으로 차단. 단위 테스트 포함.
- 대형 저장소 비용 폭주: 전역 예산과 부분 결과 계약으로 종료. 단위·통합 테스트 포함.
- Docker/OSV/OpenAI timeout: 단계별 오류와 복구 가능한 UI 메시지. mock 테스트 포함.
- 동시 UI 실행의 보고서·RAG 충돌: 단일 실행 lock, run-id 출력, RAG lock 적용.
- `.env` 경쟁 쓰기·문법 손상: 일반 파일 검증, lock, `set_key`, 원자 교체, 실패 시 원본 보존.
- 근거 없는 고위험 finding: Verifier가 제외하고 기각 사유를 내부 상태에 기록.

## NOT in scope

- 공개 네트워크 배포와 다중 사용자 인증: 이번 UI는 `127.0.0.1` 로컬 전용이다.
- 완전한 작업 큐와 분산 worker: MVP는 한 번에 한 스캔으로 제한한다.
- OS keyring 연동: `.env` opt-in 저장이 안정화된 뒤 검토한다.
- GitHub App/PR 자동 리뷰: 기존 로컬 디렉터리 분석 UX부터 완성한다.
- PyInstaller와 패키지 배포: 실행 경로 검증 후 후속 릴리스 작업으로 분리한다.

## 병렬화

순차 구현. 두 단계 모두 `core/`와 `main.py` 계약에 의존해 병렬 worktree 이득보다 충돌 위험이 크다.

## Implementation Tasks

- [ ] T1 (P1) 공통 `ScanPathPolicy` 구현 후 모든 파일 수집 경로에 적용
- [ ] T2 (P1) root-scoped MCP tools와 Semgrep 민감파일 제외 구현
- [ ] T3 (P1) structured Planner, Policy Gate, budgeted Executor, Evidence Verifier 구현
- [ ] T4 (P1) 컨텍스트·스캔 전체 예산 및 부분 결과 계약 구현
- [ ] T5 (P2) OSV 조기 종료와 consistency eval의 run-id/evidence 기준 수정
- [ ] T6 (P1) 경로·graph·예산·finding schema 회귀 테스트 작성
- [ ] T7 (P1) pipeline service, `PipelineResult`, 진행 콜백, run-id 출력 구현
- [ ] T8 (P1) localhost Streamlit UI와 안전한 API 키 opt-in 저장 구현
- [ ] T9 (P2) 단일 실행/RAG lock과 UI·CLI 계약 테스트 작성
- [ ] T10 (P2) 파일구조 이동, README와 실행 문서 갱신

## 리뷰 완료 요약

- Step 0: 두 브랜치로 범위 축소 승인
- Architecture Review: 3개 이슈, 모두 완전안 승인
- Code Quality Review: 2개 이슈, 모두 완전안 승인
- Test Review: 15개 경로 GAP 확인, 자동 테스트·eval 승인
- Performance Review: 1개 이슈, 전역·컨텍스트 예산 승인
- Outside Voice: 독립 agent 실행, 6개 보완점 모두 승인
- Cross-model tension: 없음
- Critical gaps: 구현 전 4개, 계획에 모두 포함
- Unresolved decisions: 0

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | NOT RUN | 선택 사항 |
| Codex Review | outside agent | Independent 2nd opinion | 1 | CLEAR | 6 findings accepted |
| Eng Review | `/plan-eng-review` | Architecture & tests | 1 | CLEAR | 12 issues, 4 critical gaps planned |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | NOT RUN | 2차 UI 구현 후 검토 가능 |
| DX Review | `/plan-devex-review` | Developer experience | 0 | NOT RUN | 선택 사항 |

**VERDICT:** ENG CLEARED - ready to implement

NO UNRESOLVED DECISIONS
