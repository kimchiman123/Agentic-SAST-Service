# Architecture Decision Record (ADR): 외부 검색 API(SerpAPI) 활용 및 최신 취약점 대응 전략

## 1. 개요
현재 Agentic-SAST-Guardian은 정적 코드 분석(SAST)과 ISMS-P 로컬 지식베이스(RAG)를 결합하여 취약점을 탐지하고 있습니다. 
최신 취약점(Zero-day, 최신 CVE 등) 탐지율을 높이기 위해 외부 검색 엔진 API(SerpAPI) 연동을 논의하였으나, 다음과 같은 비용/효율성 분석을 통해 '조건부 적용' 및 '위협 피드(Threat Feed) RAG 변환'이라는 결론에 도달하였습니다.

## 2. 외부 API (SerpAPI) 무조건 연동 시의 Trade-off
### 단점 (Risk & Cost)
- **API 비용 폭발 (API Explosion)**: 소스코드의 모든 부분을 인터넷에 검색할 경우 API 호출 비용과 Rate Limit 문제가 즉각적으로 발생합니다.
- **분석 지연 (Latency)**: 건당 수 초가 소요되는 웹 검색 특성상 CI/CD 파이프라인에서 블로킹 타임이 기하급수적으로 늘어납니다.
- **노이즈 증가 (Hallucination)**: SAST(Business Logic) 결함은 코드 내부의 논리적 오류이므로, 외부 블로그나 스택오버플로우 검색 결과가 오히려 에이전트의 판단을 흐리게 만듭니다.

### 장점 (Benefit)
- 의존성 라이브러리의 최신 취약점(SCA, Software Composition Analysis)을 실시간으로 캐치할 수 있습니다.

## 3. 해결 및 개선 방안 (Actionable Strategy)

### 전략 A: 조건부 트리거 및 캐싱 (Conditional Routing)
비즈니스 로직(`.js`, `.py`, `.java` 등)에는 로컬 AI 추론을 전담시키고, **패키지 명세서(`package.json`, `requirements.txt` 등)를 파싱할 때만 외부 검색 API를 활성화**시킵니다.
또한, 동일한 라이브러리/버전 검색 결과는 로컬 `.cve_cache`에 저장하여 중복 호출(비용)을 방지합니다.

### 전략 B: 정기적 위협 피드 수집 (Dynamic RAG for Zero-days)
매우 최근에 발견된 **최신 MongoDB 취약점(NoSQL Injection 우회 기법 등)**과 같은 Zero-day 위협은 검색 API에 전적으로 의존하기보다, **[위협 정보 RAG 파이프라인]**을 추가 구축하여 해결합니다.
1. 매일 주기적으로 NVD (National Vulnerability Database)나 깃허브 보안 권고문(Security Advisories)에서 최신 취약점 패턴 피드를 크롤링합니다.
2. 수집된 최신 공격 패턴을 기존 ISMS-P와 마찬가지로 로컬 ChromaDB 벡터 엔진에 추가합니다.
3. 이를 통해 API 호출 지연/비용 없이, 최신 해킹 트렌드까지 반영된 오프라인 지식베이스 기반의 초고속 분석이 가능해집니다.

## 4. 최종 결론
면접 및 실무 포트폴리오 관점에서, **"단순히 API를 호출해 해결했다"**는 접근보다 **"비용(Rate Limit, 토큰)과 속도(Latency)의 한계를 고려하여 분석 범위를 분리(SAST vs SCA)하고, 최신 위협은 DB 피드 연동 관점으로 해결하는 파이프라인(LLMOps)을 설계했다"**고 기술하는 것이 시스템 엔지니어어링 차원에서 훨씬 진보된 아키텍처입니다.
