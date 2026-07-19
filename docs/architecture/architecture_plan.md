# Agentic-SAST-Guardian Architecture & Implementation Plan

## 1. 아키텍처 개요 (Architecture Overview)
본 프로젝트는 소스코드 내부의 취약점을 분석하고 한국인터넷진흥원(KISA)의 ISMS-P 인증 규격을 준수하는지 자동으로 검증하여 보고서를 생성하는 AI Agent 파이프라인입니다. 

### 핵심 파이프라인 (V1)
1. **Semgrep 1차 분석**: 규칙 기반 정적 분석 도구를 이용한 기초 스캐닝 수행 (Known Vulnerabilities).
2. **ISMS-P RAG 지식베이스 초기화**: XLSX 세부점검항목 + PDF 안내서를 ChromaDB 벡터 DB로 구축.
3. **코드 라우팅 및 필터링**: Semgrep에서 도출된 결과와 보안상 중요한 '핵심 비즈니스 로직(인증, 결제 등)' 파일만 추출.
4. **Agent 심층 분석 & RAG 통합**: 
   - Agent가 추출된 코드의 논리적 결함(권한 우회, Race Condition 등)을 분석.
   - Vector 형태(ChromaDB)로 가공된 ISMS-P Asset에서 규정 정보를 RAG 메커니즘으로 검색 후 대조.
   - ISMS-P 위반 여부를 함께 평가하여 컴플라이언스 검증 수행.
5. **리포트 생성**: 발견된 취약점, ISMS-P 위반 사항, 개선 코드가 포함된 최종 결과를 Markdown + PDF/HTML 보고서로 출력.

*※ CVE 취약점 진단과 같은 외부 인프라/API 연동은 V1 기능의 정확도 및 RAG 파이프라인이 안정화된 이후 진행 (V2).*

---

## 2. 하네스 엔지니어링 (Harness Engineering) 전략
Agent의 출력이 오염(Hallucination)되거나 형식에서 벗어나지 않도록 강한 제어(Control)를 부여합니다.

*   **가드레일 적용:** Agent가 반드시 (1) 제공된 RAG 데이터(ISMS-P)에 근거해서만 판단하고 (2) JSON 스키마를 엄격히 지켜 리포팅하도록 System Prompt 강제.
*   **분할 정복(Divide & Conquer):** 한 번의 호출로 많은 파일을 검사하지 않고, 파일 단위 또는 함수 단위로 잘게 쪼개어(Localized Scan) 모델에 전달 (Context 한계 돌파).

---

## 3. 단계별 파이프라인 구현 계획 (Step-by-Step)

### Phase 1: 구조 스캐폴딩 및 Semgrep 연동 ✅
- [x] 터미널/CLI 형태로 구동되는 엔트리포인트(`main.py` 구조화).
- [x] 서브프로세스를 통해 타겟 프로젝트 경로의 Semgrep 자동 실행 엔진 구축 및 JSON 파싱.
- [x] 핵심 비즈니스 로직 자동 식별 및 코드 컨텍스트 추출(context_builder.py).

### Phase 2: RAG 지식베이스 초기화 (ISMS-P 에셋 처리) ✅
- [x] `asset/ISMS-P_인증기준_세부점검항목.xlsx` 구조화 파싱 (forward-fill 방식 병합 셀 처리)
- [x] `asset/ISMS-P 인증기준 안내서(2023.11.23).pdf` Text Chunking 수행 (PyMuPDF)
- [x] 로컬 ChromaDB Vector DB 구축 및 키워드 기반 Retrieval 함수 모듈화.

### Phase 3: Agent 심층 단위 분석 엔진 탑재 ✅
- [x] 하네싱이 적용된 Prompt Template 2종 작성 (Semgrep 검증용, 심층 분석용).
- [x] 파일 경로별 국소적 스캔(Localized Scan)을 수행하는 Agent Class 구축.
- [x] OpenAI GPT-5.4-mini API 연동 (JSON 구조화 출력 강제).
- [x] ISMS-P RAG 검색 결과를 Agent 프롬프트에 자동 주입.

### Phase 4: 보고서 취합 및 시각화 (PDF Export) ✅
- [x] Agent 분석 결과를 취합하는 Aggregation 모듈 구현 (심각도별 정렬/분류).
- [x] Markdown 리포트 생성 (취약점 요약 테이블 + ISMS-P 컴플라이언스 위반 요약).
- [x] Markdown → HTML (CSS 스타일) → PDF 변환 파이프라인 (pdfkit, HTML 폴백).

---

## 4. 파일 구조

```
Agentic-SAST-Guardian/
├── main.py                    # CLI 엔트리포인트 (5단계 파이프라인 오케스트레이션)
├── requirements.txt           # Python 의존성 목록
├── .env                       # API 키 (커밋 금지)
├── .gitignore                 # Git 제외 목록
├── architecture_plan.md       # 본 아키텍처 문서
├── asset/                     # ISMS-P 에셋 파일
│   ├── ISMS-P 인증기준 안내서(2023.11.23).pdf
│   └── ISMS-P_인증기준_세부점검항목.xlsx
├── core/                      # 핵심 비즈니스 로직
│   ├── __init__.py
│   ├── scanner.py             # Semgrep Docker 실행 엔진
│   ├── context_builder.py     # 코드 컨텍스트 추출 & 핵심 로직 식별
│   ├── agent.py               # OpenAI Agent (하네스 엔지니어링 적용)
│   └── isms_rag.py            # ISMS-P RAG 지식베이스 (ChromaDB)
├── utils/                     # 유틸리티
│   ├── __init__.py
│   ├── formatter.py           # Markdown 리포트 생성기
│   └── pdf_exporter.py        # PDF/HTML 변환 모듈
└── .chroma_db/                # ChromaDB 벡터 DB 캐시 (자동 생성)
```

---

## 5. 사용법

```bash
# 의존성 설치
pip install -r requirements.txt

# .env 파일에 OpenAI API 키 설정
# OPENAI_API_KEY="sk-..."

# 분석 실행 (Docker Desktop 실행 필수)
python main.py --target ./분석대상_프로젝트_경로
```

---

## 6. V2 로드맵 (추후 확장)
- [ ] CVE 취약점 진단: NVD API 연동 또는 Trivy/OSV-Scanner 통합
- [ ] Git Diff 기반 PR 리뷰 모드
- [ ] Semgrep Custom Rule 자동 생성 Agent
- [ ] PyInstaller 기반 .exe 패키징
- [ ] CI/CD 파이프라인(GitHub Actions) 통합
