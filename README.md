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
- [설계 결정 기록 (ADR)](#-설계-결정-기록-adr)
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
| **웹 검색** | DuckDuckGo Search | 최신 CVE/PoC 동향 실시간 수집 |
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
- 더 강력한 모델(`gpt-5.4-mini`)이 Chain-of-Thought(CoT) 추론을 수행합니다.
- Agent는 **MCP 도구**(`read_source`, `search_code`)를 자율적으로 호출하여 코드를 직접 읽고 함수 간 데이터 흐름을 추적합니다.
- 대용량 파일(15,000자 초과)은 **Lazy Loading** 전략을 사용하여 헤더와 함수 시그니처만 먼저 제공한 뒤, Agent가 도구를 사용해 의심 구간을 직접 탐색합니다.
- 한 번에 읽을 수 있는 코드를 300줄로 제한하여 컨텍스트 윈도우 오버플로우를 방지합니다.

#### Stage 3: Final Report + ISMS-P 매핑
- Agent의 CoT 추론 내용을 기반으로 **ChromaDB의 ISMS-P 벡터 DB를 검색**(RAG)하여, 발견된 취약점이 위반하는 인증기준 조항을 자동으로 매핑합니다.
- 필요시 **DuckDuckGo 웹 검색**을 통해 최신 CVE/PoC 동향을 수집하여 분석에 반영합니다.
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

## 📁 프로젝트 구조

```
Agentic-SAST-Service/
├── main.py                     # CLI 진입점 및 파이프라인 오케스트레이터
├── Dockerfile                  # 컨테이너 이미지 정의
├── docker-compose.yml          # 볼륨 마운트 및 환경변수 통합 실행
├── requirements.txt            # Python 의존성 목록
├── scan_project.bat            # Windows 로컬 실행 스크립트
│
├── core/                       # 핵심 분석 엔진
│   ├── agent.py                # LangGraph StateGraph 에이전트 (분석 핵심)
│   ├── scanner.py              # Semgrep Docker 실행 및 결과 파싱
│   ├── context_builder.py      # 스마트 컨텍스트 추출 (코드 스니펫 + 핵심 파일)
│   ├── isms_rag.py             # ChromaDB 기반 ISMS-P RAG 지식베이스
│   ├── mcp_tools.py            # Agent용 MCP 도구 (read_source, search_code)
│   ├── state.py                # LangGraph 상태 모델 (TypedDict)
│   └── tools/
│       ├── osv_checker.py      # OSV.dev API 의존성 취약점 스캐너
│       └── web_search.py       # DuckDuckGo 웹 검색 모듈
│
├── utils/                      # 리포트 생성 유틸리티
│   ├── formatter.py            # 분석 결과 → 마크다운 변환 (보안 점수, 대시보드)
│   └── pdf_exporter.py         # 마크다운 → HTML/PDF 변환 (프리미엄 CSS 디자인)
│
├── asset/                      # ISMS-P 규정 원본 자료
│   ├── ISMS-P 인증기준 안내서(2023.11.23).pdf
│   └── ISMS-P_인증기준_세부점검항목.xlsx
│
└── reports/                    # 생성된 분석 리포트 저장 디렉토리
```

---

## 🚀 실행 방법

### 사전 요구사항

- **Docker Desktop** 이 설치되고 실행 중이어야 합니다 (Semgrep 스캐너 실행에 필요)
- **OpenAI API Key** 가 필요합니다

### 방법 1. Docker Compose (권장)

```bash
# 1. 프로젝트 클론
git clone https://github.com/kimchiman123/Agentic-SAST-Service.git
cd Agentic-SAST-Service

# 2. 환경변수 설정
echo "OPENAI_API_KEY=sk-your-key-here" > .env

# 3. 스캔할 대상 프로젝트를 target_project/ 폴더에 배치
cp -r /path/to/your/project ./target_project

# 4. Docker로 분석 실행
docker-compose up --build
```

리포트는 `./reports/` 폴더에 자동 저장됩니다.

### 방법 2. Docker 직접 실행

```bash
# 이미지 빌드
docker build -t agentic-sast-guardian .

# 실행 (대상 경로와 리포트 경로를 마운트)
docker run --rm \
  -v "/path/to/your/project:/target" \
  -v "$(pwd)/reports:/app/reports" \
  --env-file .env \
  agentic-sast-guardian --target /target
```

### 방법 3. 로컬 직접 실행 (Windows)

```bash
# 의존성 설치
pip install -r requirements.txt
pip install semgrep

# ripgrep 설치 (코드 검색 도구)
# https://github.com/BurntSushi/ripgrep/releases

# 실행
python main.py --target ./vuln-test-app
```

또는 `scan_project.bat` 파일을 더블클릭하여 실행할 수 있습니다.

---

## 📊 산출물

실행이 완료되면 `reports/` 디렉토리에 다음 파일들이 생성됩니다.

```
reports/
├── {대상폴더명}_{YYYYMMDD_HHMMSS}.pdf     # 보안 분석 PDF 보고서 (대시보드 + 상세 분석)
└── {대상폴더명}_{YYYYMMDD_HHMMSS}.xlsx    # 취약점 상세 내역 엑셀
```

PDF 리포트에는 **보안 점수(0-100)**, **등급별 통계 카드**, **ISMS-P 위반 현황 테이블**이 포함된 Executive Dashboard가 첫 페이지에 배치됩니다.

---

## 📄 분석 사례

이전에 AWS EKS 서버를 구축했던 프로젝트를 Agentic-SAST-Guardian으로 분석하여, 취약점과 개선점을 PDF 문서로 산출하였습니다.

| 항목 | 내용 |
|:---|:---|
| **분석 대상 레포지토리** | [🔗 kimchiman123/mini_project5](https://github.com/kimchiman123/mini_project5) |
| **분석 결과 PDF 보고서** | [📄 EKS_20260426_154728.pdf](reports/EKS_20260426_154728.pdf) |
| **취약점 상세 내역 (Excel)** | [📊 EKS_20260426_154728.xlsx](reports/EKS_20260426_154728.xlsx) |

> 해당 프로젝트는 Spring Boot 백엔드, React 프론트엔드, Nginx 리버스 프록시, Docker Compose 기반으로 구성된 AWS EKS 배포 서비스입니다.
> SAST 분석을 통해 CORS 설정, SQL 인젝션, 컨테이너 권한 설정, OAuth 인증 흐름 등 다수의 보안 취약점이 탐지되었으며, 각 항목에 대한 ISMS-P 규정 매핑과 구체적인 수정 가이드가 보고서에 포함되어 있습니다.

---

## 📐 설계 결정 기록 (ADR)

### 1. 왜 2단계 모델 전략(nano → mini)인가?

모든 코드 컨텍스트에 고성능 모델을 투입하면 토큰 비용이 기하급수적으로 증가합니다. 가벼운 nano 모델로 1차 필터링(Discovery)을 수행해 안전한 코드를 걸러내고, 실제 의심 구간에만 mini 모델을 집중 투입합니다. Toss 기술 블로그의 "취약점 분석 자동화" 사례에서 영감을 받은 구조입니다.

### 2. 왜 Lazy Loading인가?

15,000자 이상의 대용량 파일을 한 번에 LLM에 전달하면 컨텍스트 윈도우가 포화되어 분석 품질이 떨어집니다. 파일 상단 50줄과 함수/클래스 시그니처 목록만 먼저 제공한 뒤, Agent가 MCP 도구를 사용해 의심 구간을 직접 탐색하는 "능동적 분석" 방식을 채택했습니다.

### 3. 왜 RAG 쿼리에 CoT를 사용하는가?

초기에는 코드 스니펫의 앞 500자를 검색 쿼리로 사용했으나, 코드 텍스트만으로는 "이 코드가 어떤 보안 규정과 관련 있는지" 맥락을 잡기 어려웠습니다. Agent가 생성한 Chain-of-Thought 추론 결과를 검색 쿼리로 사용하면, "비밀번호 일방향 암호화 미적용"과 같은 보안 키워드가 포함되어 ISMS-P 규정 매칭 정확도가 크게 향상됩니다.

### 4. 왜 2단계 JSON 파싱 Fallback인가?

LLM의 Structured Output 기능은 가끔 마크다운 백틱이나 사족을 포함한 불완전한 JSON을 반환합니다. 1차로 `with_structured_output`을 시도하고, 실패 시 일반 텍스트 모드로 재호출 후 정규표현식으로 JSON 블록만 추출하는 2단계 방어 전략을 적용합니다.

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
