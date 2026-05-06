# 세션 기록 (Session Log)

| Date | 작업 디렉토리 | 파일명 | 작업 내용 한 줄 요약 (한글) |
|---|---|---|---|
| 2026-04-20 | core | state.py | AnalysisState에 Multi-Agent 필터링 상태(is_vulnerable_candidate) 필드 추가 |
| 2026-04-20 | core | mcp_tools.py | Analysis Agent 지원용 코드 탐색/검색(read_source, ripgrep) MCP 도구 생성 |
| 2026-04-20 | core | agent.py | Discovery(nano) & Analysis(mini) 노드 분리 및 LangGraph Multi-Agent 구조 개편 |
| 2026-04-20 | . | scan_project.bat | 타겟 폴더 누락 시 테스트 폴더(vuln-test-app) 자동 선택 로직 제거 및 종료 처리 |
| 2026-04-20 | . | scan_project.bat | 타겟 폴더 누락 시 종료되지 않고 경로 입력을 대기하도록 반복(Loop) 로직 추가 |
| 2026-04-20 | core | agent.py | ThreadPoolExecutor를 사용한 비동기 병렬 처리 도입 및 JSON 출력 파싱 프롬프트 강화 |
| 2026-04-20 | core/tools | web_search.py | duckduckgo_search 경고 해결을 위해 모듈 명을 ddgs로 업데이트 |
| 2026-05-06 | . | (multiple) | RAG 및 평가 관련 파일들을 test 폴더로 이동 (evaluate_rag.py, test_rag.py, RAG품질_평가.md, rag_evaluation_results.csv, vuln-test-app) |
| 2026-05-06 | test | eval_dataset.json | 정량 평가를 위한 취약점 정답지(Ground Truth) 데이터셋 생성 |
| 2026-05-06 | test | eval_method_a.py | 단일 에이전트(No-CoT) 성능 및 토큰 평가용 스크립트 템플릿 생성 |
| 2026-05-06 | test | eval_method_b.py | 멀티 에이전트(CoT) 성능 및 토큰 평가용 스크립트 템플릿 생성 |
| 2026-05-06 | test | calculate_metrics.py | 정량 평가(Precision, Recall, F1-Score) 계산 스크립트 생성 |
| 2026-05-06 | test | eval_dataset.json | 한국어 전면 개편 및 CWE/ISMS-P 매핑 포함 10개 취약점으로 확장 |
| 2026-05-06 | test | calculate_metrics.py | 새 데이터셋 구조에 맞게 키워드+라인 이중 매칭, 심각도별 탐지율 분석 기능으로 전면 개편 |
| 2026-05-06 | test | eval_method_a.py | 실제 LLM API 호출 기반 단일 에이전트(No-CoT) 평가 스크립트로 전면 개편 |
| 2026-05-06 | test | eval_method_b.py | 실제 LLM API 호출 기반 멀티 에이전트(Nano+Mini, CoT) 평가 스크립트로 전면 개편 |
| 2026-05-06 | test | result_method_a.json | 방식 A 실행 결과 저장 (토큰 1,399 / 탐지 4개) |
| 2026-05-06 | test | result_method_b.json | 방식 B 실행 결과 저장 (토큰 3,524 / 탐지 4개) |
| 2026-05-06 | test | AB_테스트_결과_리포트.md | A/B 테스트 종합 결과 리포트 작성 (토큰, F1-Score, 정성 분석) |
