<p align="center">
  <h1 align="center">🛡️ Agentic-SAST-Guardian</h1>
  <p align="center">
    <strong>AI 에이전트 기반 정적 보안 분석 도구 + ISMS-P 컴플라이언스 자동 매핑</strong>
  </p>
  <p align="center">
    Semgrep × LangGraph × RAG 를 결합한 하이브리드 SAST 파이프라인
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/LangGraph-StateGraph-FF6F00?logo=langchain&logoColor=white" />
  <img src="https://img.shields.io/badge/Semgrep-SAST-4B275F?logo=semgrep&logoColor=white" />
  <img src="https://img.shields.io/badge/ChromaDB-RAG-00A67E" />
  <img src="https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/ISMS--P-Compliance-DC143C" />
</p>

---

## 📋 목차

- [프로젝트 배경](#-프로젝트-배경)
- [핵심 아이디어](#-핵심-아이디어)
- [기술 스택](#-기술-스택)
- [시스템 아키텍처](#-시스템-아키텍처)
- [파이프라인 상세](#-파이프라인-상세)
- [프로젝트 구조](#-프로젝트-구조)
- [실행 방법](#-실행-방법)
- [산출물](#-산출물)
- [분석 사례](#-분석-사례)
- [핵심 설계 전략](#-핵심-설계-전략)
- [참고 자료](#-참고-자료)

---

## 🎯 프로젝트 배경

### ISMS-P 인증, 왜 자동화가 필요한가?

**ISMS-P(정보보호 및 개인정보보호 관리체계 인증)** 는 국내에서 일정 규모 이상의 기업이 의무적으로 취득해야 하는 보안 인증입니다. 인증 심사 시 소스코드 보안 취약점 점검은 필수 항목이며, 이를 준비하는 데에는 다음과 같은 현실적인 문제가 있습니다.

| 현실적 문제 | 구체적 사례 |
|:---|:---|
| **높은 비용** | 외부 보안 컨설팅 업체의 모의해킹 및 소스코드 점검은 건당 수천만 원의 비용이 발생합니다. |
| **인력 부족** | 코드를 라인 단위로 분석할 수 있는 시니어 보안 엔지니어의 수가 절대적으로 부족합니다. |
| **반복적 작업** | 인증 갱신 주기마다 동일한 점검 절차를 수작업으로 반복해야 하며, 보고서 양식도 수동으로 작성합니다. |
| **높은 오탐률** | Semgrep, SonarQube 등 기존 SAST 도구의 FP(False Positive) 비율은 40~60%에 달해, 결과의 신뢰성이 낮습니다. |

**Agentic-SAST-Guardian**은 이 문제를 해결하기 위해 설계되었습니다. 기존 SAST 도구가 "발견만 하고 끝"이었다면, 이 시스템은 **"발견 → AI 검증 → 비즈니스 로직 심층 분석 → ISMS-P 규정 매핑 → 개선 가이드 산출"** 까지의 전 과정을 하나의 자율 에이전트 파이프라인으로 자동화합니다.

---

## 💡 핵심 아이디어

> 기존 SAST 도구(Semgrep)의 **"패턴 매칭"** 한계를 AI Agent의 **"문맥 이해"** 능력으로 보완하고,
> 발견된 취약점을 한국 규제(ISMS-P)에 자동으로 매핑하여 실무에 바로 쓸 수 있는 보고서를 생성합니다.

### 기존 도구와의 차별점

| 구분 | 기존 SAST (Semgrep 단독) | Agentic-SAST-Guardian |
|:---|:---|:---|
| 분석 방식 | 정규식 패턴 매칭 | 패턴 매칭 + AI 문맥 분석 |
| 오탐 처리 | 수동 검증 필요 | Agent가 코드 문맥을 읽고 자동 FP 판별 |
| 비즈니스 로직 결함 | 탐지 불가 | IDOR, Race Condition 등 논리적 결함 탐지 |
| 컴플라이언스 매핑 | 별도 수작업 | RAG 기반 ISMS-P 위반 사항 자동 매핑 |
| 수정 가이드 | 없음 또는 일반적 권고 | 코드 레벨의 구체적 Remediation 패치 제공 |
| 의존성 취약점 | 별도 SCA 도구 필요 | OSV.dev API 연동으로 자동 검출 |

---

## 🛠 기술 스택

| 영역 | 기술 | 역할 |
|:---|:---|:---|
| **정적 분석** | Semgrep (Docker) | OWASP 기반 패턴 매칭 스캐닝 |
| **AI Engine** | OpenAI GPT (LangChain) | 취약점 검증, 심층 분석, 보고서 생성 |
| **Agent Framework** | LangGraph (StateGraph) | 다단계 분석 워크플로우 오케스트레이션 |
| **Agent Tools** | MCP Tools (read_source, search_code) | 에이전트의 자율적 코드 탐색 도구 |
| **RAG** | ChromaDB + PyMuPDF + openpyxl | ISMS-P 규정 문서의 벡터 검색 |
| **SCA** | OSV.dev API | npm 의존성 패키지 취약점 검출 |
| **웹 검색** | DDGS (기본 비활성) | 명시적으로 허용한 CVE/CWE 조회 |
| **리포트** | Markdown + HTML/PDF (wkhtmltopdf) | 전문가 수준의 프리미엄 분석 보고서 |
| **컨테이너** | Docker / Docker Compose | 재현 가능한 런타임 환경 보장 |

---

## 🏗 시스템 아키텍처

```
┌────────────────────────────────────────────────────────────────┐
│                    Agentic-SAST-Guardian                        │
│                                                                │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────────┐ │
│  │  Phase 1  │    │   Phase 2    │    │       Phase 3         │ │
│  │  Semgrep  │───▶│ Context      │───▶│   AI Agent Pipeline   │ │
│  │  SAST     │    │ Extraction   │    │                       │ │
│  └──────────┘    └──────────────┘    │  ┌─────────────────┐  │ │
│                                       │  │ Stage 1: nano   │  │ │
│  ┌──────────┐                        │  │ Discovery Filter│  │ │
│  │ Phase 1.5│                        │  └────────┬────────┘  │ │
│  │ OSV.dev  │─────────────────────┐  │           │           │ │
│  │ SCA      │                     │  │  ┌────────▼────────┐  │ │
│  └──────────┘                     │  │  │ Stage 2: mini   │  │ │
│                                   │  │  │ Deep Analysis   │  │ │
│  ┌──────────┐                     │  │  │ + MCP Tools     │  │ │
│  │ ISMS-P   │                     │  │  └────────┬────────┘  │ │
│  │ RAG KB   │─────────────────────┤  │           │           │ │
│  │(ChromaDB)│                     │  │  ┌────────▼────────┐  │ │
│  └──────────┘                     └──┤  │ Stage 3: Report │  │ │
│                                      │  │ + ISMS-P 매핑   │  │ │
│                                      │  │ + Web Search    │  │ │
│                                      │  └────────┬────────┘  │ │
│                                         └────────┼───────────┘ │
│                                                  │             │
│  ┌───────────────────────────────────────────────▼───────────┐ │
│  │                Phase 4: Report Generation                 │ │
│  │   Markdown  │  HTML/PDF  │  JSON (CI/CD)  │  CSV (KPI)   │ │
│  └───────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔍 파이프라인 상세

### Phase 1. 정적 분석 (Semgrep SAST)

Docker 기반 Semgrep을 실행하여 OWASP Top 10 등 알려진 패턴의 취약점을 빠르게 탐지합니다.

- **입력:** 대상 프로젝트 소스코드 디렉토리
- **출력:** 규칙 ID, 심각도, 취약 라인, 코드 스니펫이 포함된 JSON 결과
- **구현:** `core/scanner.py` → `SemgrepRunner`

### Phase 1.5. 의존성 취약점 스캔 (OSV.dev SCA)

`package.json` 등에서 의존성 목록을 추출하고, [OSV.dev](https://osv.dev/) API를 통해 알려진 CVE를 조회합니다.

- **구현:** `core/tools/osv_checker.py` → `scan_dependencies()`

### Phase 2. 스마트 컨텍스트 추출

Semgrep이 탐지한 취약 라인의 **앞뒤 50줄**을 포함한 코드 스니펫과 프로젝트 디렉토리 구조를 수집합니다. 동시에 `auth`, `payment`, `session` 등 보안상 중요한 키워드가 포함된 핵심 비즈니스 로직 파일들을 별도로 식별합니다.

- **구현:** `core/context_builder.py` → `ContextExtractor`

### Phase 3. AI Agent 심층 분석 (LangGraph)

LangGraph의 `StateGraph`를 사용한 **3단계 멀티 에이전트 파이프라인**이 핵심입니다.

#### Stage 1: Discovery Filter (nano 모델)
- 가벼운 모델(`gpt-5.4-nano`)이 각 코드 컨텍스트를 사전 검토하여 취약점 가능성이 있는 항목만 다음 단계로 전달합니다.
- **목적:** 안전한 코드는 빠르게 스킵하여 토큰 비용과 분석 시간을 절감합니다.

#### Stage 2: Deep Analysis (mini 모델 + MCP Tools)
- 더 강력한 모델(`gpt-5.4-mini`)이 승인된 조사 계획에 따라 근거를 수집합니다.
- Agent는 **MCP 도구**(`read_source`, `search_code`)를 자율적으로 호출하여 코드를 직접 읽고 함수 간 데이터 흐름을 추적합니다.
- 대용량 파일(15,000자 초과)은 **Lazy Loading** 전략을 사용하여 헤더와 함수 시그니처만 먼저 제공한 뒤, Agent가 도구를 사용해 의심 구간을 직접 탐색합니다.
- 한 번에 읽을 수 있는 코드를 300줄로 제한하여 컨텍스트 윈도우 오버플로우를 방지합니다.

#### Stage 3: Final Report + ISMS-P 매핑
- 조사 계획의 RAG 쿼리를 기반으로 **ChromaDB의 ISMS-P 벡터 DB를 검색**하여 인증기준 조항을 자동으로 매핑합니다.
- 외부 검색은 기본 비활성이며, 코드에서 명시적으로 활성화한 경우에도 알려진 CVE/CWE 또는 OSV 패키지만 조회합니다.
- 최종 결과를 Pydantic 구조화 출력으로 정리합니다. LLM 응답 파싱 실패 시 JSON 블록을 정규표현식으로 추출하는 2단계 Fallback 로직이 적용되어 있습니다.

### Phase 4. ISMS-P RAG 지식베이스

`asset/` 디렉토리에 포함된 ISMS-P 공식 문서를 파싱하여 벡터 DB를 구축합니다.

- **XLSX:** 세부점검항목 엑셀 (병합 셀 Forward-Fill 처리)
- **PDF:** 인증기준 안내서 (1,500자 단위 청킹, 조항 번호 자동 추출)
- 코드 분석 시 보안 키워드를 자동 확장(Query Expansion)하여 검색 정확도를 높입니다.
- **구현:** `core/isms_rag.py` → `ISMSKnowledgeBase`

### Phase 5. 리포트 생성

분석 결과를 **2가지 포맷**으로 산출합니다.

| 산출물 | 포맷 | 용도 |
|:---|:---|:---|
| 보안 분석 보고서 | `.pdf` | 경영진/보안팀 보고용 (대시보드 + 보안 점수 + 상세 분석) |
| 취약점 상세 내역 | `.xlsx` | 실무 조치용 엑셀 (심각도별 필터링, 수정 가이드 포함) |

---

## 프로젝트 구조

```
Agentic-SAST-Service/
├── main.py                     # 얇은 CLI 진입점
├── run_ui.bat                  # localhost 전용 UI 실행기
├── requirements.txt            # Python 의존성 목록
├── core/                       # 핵심 분석 엔진
│   ├── pipeline.py             # CLI/UI 공용 파이프라인 서비스
│   ├── config.py               # API 키 검증 및 선택적 저장
│   ├── agent.py                # LangGraph StateGraph 에이전트 (분석 핵심)
│   ├── path_policy.py          # 스캔 루트 및 민감 파일 경계 정책
│   ├── scanner.py              # Semgrep Docker 실행 및 결과 파싱
│   ├── context_builder.py      # 스마트 컨텍스트 추출 (코드 스니펫 + 핵심 파일)
│   ├── isms_rag.py             # ChromaDB 기반 ISMS-P RAG 지식베이스
│   ├── mcp_tools.py            # Agent용 MCP 도구 (read_source, search_code)
│   ├── state.py                # LangGraph 상태 모델 (TypedDict)
│   └── tools/
│       ├── osv_checker.py      # OSV.dev API 의존성 취약점 스캐너
│       └── web_search.py       # 제한된 외부 보안 검색 모듈
├── ui/                         # Streamlit 로컬 UI
├── tests/                      # unit, integration, fixtures
├── benchmarks/                 # RAG 및 agent consistency 평가
├── docs/                       # architecture, experiments, plans
├── utils/                      # 리포트 생성 유틸리티
│   ├── formatter.py            # 분석 결과 → 마크다운 변환 (보안 점수, 대시보드)
│   └── pdf_exporter.py         # 마크다운 → HTML/PDF 변환 (프리미엄 CSS 디자인)
│
├── asset/                      # ISMS-P 규정 원본 자료
│   ├── ISMS-P 인증기준 안내서(2023.11.23).pdf
│   └── ISMS-P_인증기준_세부점검항목.xlsx
│
└── reports/generated/{run-id}/ # 실행별 생성 산출물 (Git 제외)
```

---

## 실행 방법

### 사전 요구사항

- **Docker Desktop**이 설치되고 실행 중이어야 합니다 (Semgrep 컨테이너 실행)
- **OpenAI API Key** 가 필요합니다
- Python 3.11 이상과 `ripgrep`이 필요합니다

### 방법 1. 로컬 UI (권장)

```bash
git clone https://github.com/kimchiman123/Agentic-SAST-Service.git
cd Agentic-SAST-Service
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
run_ui.bat
```

브라우저에서 API 키와 대상 폴더를 입력합니다. 키는 기본적으로 현재 실행에만 사용되며, 사용자가 `이 기기에 저장 (.env)`를 선택한 경우에만 프로젝트 루트 `.env`에 저장됩니다. UI는 `127.0.0.1`에만 바인딩되며 원격 배포는 지원하지 않습니다.

### 방법 2. CLI

```bash
copy .env.example .env
# .env의 OPENAI_API_KEY 값을 설정한 뒤:
python main.py --target C:\path\to\project
```

CLI는 `scan_project.bat`로도 실행할 수 있습니다.

---

## 산출물

실행이 완료되면 충돌하지 않는 run-id 디렉터리에 결과가 생성됩니다.

```
reports/
└── generated/{YYYYMMDD_HHMMSS}_{random}/
    ├── {대상폴더명}.pdf 또는 .html
    ├── {대상폴더명}.xlsx
    └── {대상폴더명}.json
```

PDF 리포트에는 **보안 점수(0-100)**, **등급별 통계 카드**, **ISMS-P 위반 현황 테이블**이 포함된 Executive Dashboard가 첫 페이지에 배치됩니다.

---

실험 기록과 과거 평가 결과는 `docs/experiments/`, 재현 가능한 입력과 baseline은 `benchmarks/`에서 확인할 수 있습니다.

---

## 📐 핵심 설계 전략

### 1. 2단계 모델 파이프라인 (nano → mini)

| 항목 | 설계 | 동작 | 효과 |
|:---|:---|:---|:---|
| **Discovery Filter** | 경량 모델(`gpt-5.4-nano`)로 1차 필터링 | 각 코드 컨텍스트를 사전 검토하여 안전한 코드는 스킵 | 불필요한 토큰 소비 차단 |
| **Deep Analysis** | 고성능 모델(`gpt-5.4-mini`)로 2차 정밀 분석 | Planner의 조사 계획과 전역 예산 안에서만 도구 호출 | 비용 대비 분석 정확도 극대화 |

### 2. Lazy Loading (대용량 파일 처리)

| 항목 | 설계 | 동작 | 효과 |
|:---|:---|:---|:---|
| **시그니처 우선 제공** | 15,000자 초과 파일은 상단 50줄 + 함수/클래스 시그니처만 전달 | Agent가 전체 구조를 파악한 뒤 의심 구간을 MCP 도구로 직접 탐색 | 컨텍스트 윈도우 포화 방지 |
| **300줄 읽기 제한** | 한 번의 도구 호출당 최대 300줄로 제한 | 필요한 코드만 선별적으로 로드 | 토큰 낭비 없이 정밀 분석 수행 |

### 3. 계획 기반 RAG 검색 (ISMS-P 매핑)

| 항목 | 설계 | 동작 | 효과 |
|:---|:---|:---|:---|
| **계획 → 검색 쿼리** | Planner가 만든 제한된 RAG 쿼리를 활용 | 보안 가설과 확인 항목을 검색에 반영 | 코드 텍스트 직접 검색 대비 매칭 정확도 향상 |
| **Query Expansion** | 보안 키워드 동의어를 자동 확장 | "SQL Injection" → "SQL 삽입", "입력값 검증" 등으로 확장 검색 | 한국어/영어 혼용 규정 문서에서도 높은 Recall 확보 |

### 4. 2단계 JSON 파싱 Fallback

| 항목 | 설계 | 동작 | 효과 |
|:---|:---|:---|:---|
| **1차 시도** | Pydantic `with_structured_output` 호출 | LLM에 JSON 스키마를 강제하여 구조화된 응답 요청 | 정상 케이스에서 즉시 파싱 |
| **2차 Fallback** | 일반 텍스트 모드 재호출 + 정규표현식 추출 | 마크다운 백틱 등 불완전한 JSON에서 유효 블록만 추출 | 파싱 실패율 최소화, 파이프라인 안정성 보장 |

---

## 📎 참고 자료

- [Toss 기술 블로그 - 취약점 분석 자동화 (1편)](https://toss.tech/article/vulnerability-analysis-automation-1)
- [Toss 기술 블로그 - 취약점 분석 자동화 (2편)](https://toss.tech/article/vulnerability-analysis-automation-2)
- [KISA - ISMS-P 인증기준 안내서 (2023.11)](https://isms.kisa.or.kr/)
- [OSV.dev - Open Source Vulnerabilities](https://osv.dev/)

---

<p align="center">
  <sub>이 프로젝트는 보안 점검 자동화의 가능성을 증명하기 위한 연구 목적으로 개발되었습니다.</sub><br>
</p>
