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
