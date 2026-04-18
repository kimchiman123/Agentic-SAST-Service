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

### 전략 B: 온디맨드(On-demand) OSV.dev API 연동 (의존성 검증)
개인 프로젝트 파일럿이나 오픈소스 도구 특성상, 24시간 도는 자체 백엔드(크롤러+DB)를 운영하는 것은 비효율적입니다.
대신, 구글이 유지보수하는 무료 취약점 데이터베이스 API인 **OSV(Open Source Vulnerabilities) API**를 활용합니다.
1. 스크립트 실행 시 `package.json`, `requirements.txt`에 명시된 라이브러리와 버전 리스트만 추출합니다.
2. 이를 OSV API 블록에 일괄 전송(Batch Query)하여, "현재 버전에 알려진 최신 취약점(예: 몽고DB 드라이버 최신 우회기법)" 정보를 1초 내로 받아옵니다.
3. 이를 Agent의 프롬프트 컨텍스트에 주입하여, Agent가 코드 로직 분석 시 해당 취약점이 터질 수 있는 조건인지 판단하게 합니다.

### 전략 C: 커뮤니티 주도 패턴 엔진 활용 (Semgrep Registry Sync)
SAST(정적 분석) 관점에서 최신 몽고DB 인젝션 기법이나 제로데이를 잡아내려면, **Semgrep의 글로벌 레지스트리(Community Rules)**를 스캔 직전에 최신화하는 구조를 채택합니다.
1. 전 세계 보안 리서처들이 매일 깃허브에 최신 제로데이 탐지 패턴(Rule)을 올립니다.
2. 에이전트는 무거운 웹 검색을 하지 않아도, 스캔 엔진 구동 전 `semgrep update` 명령을 실행하여 최신 룰 파이프라인을 항상 유지(Pull)합니다.
3. 이 패턴에 탐지된 내역만 AI가 검증함으로써 효율을 극대화합니다.

## 4. 최종 결론
면접 및 실무 포트폴리오 관점에서, **"무작위 웹 검색(SerpAPI)이나 무거운 자체 서버형 크롤러를 지양하고, OSV API 일괄 조회(SCA)와 글로벌 보안 커뮤니티 엔진(Semgrep)의 동기화를 결합하여, 로컬 환경(CLI/오픈소스)에서도 API 비용 소진 없이 최신(Zero-day) 취약점을 완벽하게 커버하는 경량화된 아키텍처를 설계했다"**고 어필하는 것이 가장 현실적이고 훌륭한 엔지니어링 접근법입니다.
