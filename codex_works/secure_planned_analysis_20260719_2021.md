# 작업 요약

## 작업 목표
- 스캔 파일 접근을 대상 루트로 제한한다.
- 계획, 실행, 증거 검증을 분리하고 전역 실행 예산을 적용한다.

## 변경 파일
- `core/agent.py`, `core/path_policy.py`, `core/mcp_tools.py`
- `core/context_builder.py`, `core/scanner.py`, `core/tools/`
- `main.py`, `requirements.txt`, `requirements-dev.txt`
- `tests/unit/`, `docs/plans/`

## 주요 변경사항
- 민감 파일과 루트 외부 경로 접근 차단
- Planner → Budgeted Executor → Evidence Verifier 흐름 추가
- Semgrep 위치에서 서버가 증거 스니펫과 SHA-256을 생성해 재검증
- 도구, LLM, 컨텍스트, finding, 재귀 횟수 제한 추가
- OSV 검사를 빈 코드 결과보다 먼저 실행

## 검증 결과
- `compileall` 통과
- `pytest`: 23 passed, 2 skipped, 14 subtests passed
- `git diff --check` 통과
- 독립 보안 검토에서 커밋 차단 이슈 없음

## 미해결 사항
- Windows symlink/junction 테스트 2건은 실행 권한이 없어 skip될 수 있음
- 실제 OpenAI API 호출과 Docker Semgrep 통합 테스트는 수행하지 않음

## 추가 권장사항
- UI에서 외부 검색을 활성화할 경우 검색 템플릿을 고정 allowlist로 제한
