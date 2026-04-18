"""
LangGraph 기반 AI 에이전트 심층 분석 모듈.
GPT 모델을 활용하여 Semgrep 결과 검증 및 비즈니스 로직 취약점을 파악하며,
향후 외부 도구(OSV, SerpAPI) 연동이 가능하도록 상태(StateGraph) 기반 워크플로우로 설계되었습니다.
"""
import os
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, START, END

from core.isms_rag import ISMSKnowledgeBase
from core.state import AnalysisState


# ──────────────────────────────────────────────
#  1) Pydantic 모델 정의 (Structured Output)
# ──────────────────────────────────────────────

class FindingModel(BaseModel):
    rule_id: Optional[str] = Field(default=None, description="semgrep 규칙 ID")
    is_true_positive: bool = Field(default=True, description="오탐 여부")
    false_positive_reason: Optional[str] = Field(default=None, description="오탐일 경우 그 사유")
    severity: str = Field(default="INFO", description="CRITICAL | HIGH | MEDIUM | LOW | INFO")
    title: str = Field(default="제목 없음", description="취약점 제목 (한국어)")
    description: str = Field(default="", description="취약점 상세 설명 (한국어)")
    vulnerability_type: Optional[str] = Field(default=None, description="IDOR | Race Condition | Logic Bypass 등")
    file_path: Optional[str] = Field(default=None, description="취약점이 위치한 파일 경로")
    taint_analysis: Optional[str] = Field(default=None, description="데이터 흐름 추적 설명")
    exploit_scenario: str = Field(default="", description="상세 공격 시나리오")
    affected_code: str = Field(default="", description="취약한 코드 라인")
    remediation_code: str = Field(default="", description="수정된 안전한 코드")
    remediation_description: str = Field(default="", description="수정 방법 설명 (한국어)")
    isms_p_violation: Optional[str] = Field(default=None, description="ISMS-P 위반 사항")

class OutputModel(BaseModel):
    findings: List[FindingModel] = Field(default_factory=list)


# ──────────────────────────────────────────────
#  2) 시스템 프롬프트
# ──────────────────────────────────────────────

SYSTEM_PROMPT_SEMGREP_ANALYSIS = """당신은 클라우드 네이티브 환경에서 10년 이상 경력을 가진 수석 보안 감사관(Senior Security Auditor)입니다.

## 역할
Semgrep 정적 분석 도구가 탐지한 취약점 결과를 검증하고, 오탐(False Positive)을 필터링한 뒤 실제 위험이 존재하는 항목에 대해 데이터 흐름(Taint Analysis), 공격 시나리오, 그리고 안전한 수정 코드를 제시합니다.

## 입력 데이터
- Semgrep이 탐지한 취약점 정보 (규칙 ID, 심각도, 메시지)
- 해당 취약점이 위치한 코드의 앞뒤 50줄 스니펫 (취약 라인은 >>> 마커로 표시됨)
- 프로젝트 디렉토리 구조

## 분석 지침
1. 제공된 코드 스니펫만을 근거로 판단하세요. 추측이나 가정을 하지 마세요.
2. 오탐(False Positive)인 경우, 'is_true_positive'를 false로 설정하고 'false_positive_reason'에 명확한 논거를 제시하세요.
3. 실제 취약점(True Positive)인 경우, 데이터가 어디서 입력되어(Source) 어디서 취약점이 터지는지(Sink) 설명하는 'taint_analysis'를 작성하세요.
4. 구체적인 공격 시나리오(PoC)와 수정 코드를 작성하세요.
5. 심각도를 재평가하여 CRITICAL | HIGH | MEDIUM | LOW | INFO 중 하나로 분류하세요.
6. ISMS-P 관련 규약이 함께 제공된 경우, 해당 규약의 위반 여부도 반드시 평가하세요."""

SYSTEM_PROMPT_DEEP_ANALYSIS = """당신은 클라우드 네이티브 환경 및 금융/보안 도메인에 정통한 수석 보안 감사관(Senior Security Auditor)입니다.

## 역할
일반적인 정적 분석 도구(SAST)나 패턴 매칭으로는 발견하기 어려운 **'비즈니스 로직 결함(Business Logic Vulnerabilities)'**을 식별하는 심층 코드 감사(Code Audit)를 수행합니다.

## 중점 분석 항목
1. **인가 검증 누락 (Broken Access Control):** ID조작으로 타인 리소스 접근 가능 여부 (IDOR)
2. **경쟁 상태 (Race Condition):** 동시 다발적 요청에 대한 데이터 무결성 훼손 여부
3. **입력값 검증에 따른 로직 우회:** 비정상 파라미터를 이용한 우회
4. **상태 관리 결함:** 토큰/세션 상태 검증 누락
5. **민감 정보 노출:** 로그, 응답 에러 메시지를 통한 노출

## 분석 지침
1. 제공된 코드만을 근거로 판단하세요. 일반적 문법 오류나 Lint 경고는 무시하세요.
2. 실제 해커 관점에서 타격을 줄 수 있는 익스플로잇 가능한 시나리오와 데이터 흐름(Taint Analysis)만 기술하세요.
3. 취약점이 없으면 빈 배열을 반환하세요."""


# ──────────────────────────────────────────────
#  3) LangGraph 기반 Agent 클래스
# ──────────────────────────────────────────────

class OpenAIAgent:
    """
    Phase 1: LangGraph 기반으로 리팩토링된 최신 Agent.
    """

    # GPT 모델명 (환경에 따라 변경 가능)
    MODEL_NAME = "gpt-5.4-mini"

    def __init__(self, isms_kb: Optional[ISMSKnowledgeBase] = None) -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("[!] OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

        # Langchain ChatModel 인스턴스 (Pydantic 아웃풋 적용)
        self.llm = ChatOpenAI(model=self.MODEL_NAME, api_key=api_key, temperature=0.1)
        self.structured_llm = self.llm.with_structured_output(OutputModel)
        
        self.isms_kb = isms_kb
        self.graph = self._build_graph()

    def _build_graph(self):
        """LangGraph 워크플로우를 조립합니다."""
        workflow = StateGraph(AnalysisState)
        
        # 메인 분석 노드
        workflow.add_node("analyze_node", self._analyze_node)
        
        # 간단한 단방향 파이프라인 (Phase 1)
        workflow.add_edge(START, "analyze_node")
        workflow.add_edge("analyze_node", END)
        
        return workflow.compile()

    def _analyze_node(self, state: AnalysisState) -> AnalysisState:
        """단일 컨텍스트에 대해 LLM 분석을 수행하는 노드"""
        ctx = state["context"]
        ctype = state["context_type"]
        
        if ctype == "semgrep":
            system_prompt = SYSTEM_PROMPT_SEMGREP_ANALYSIS
            user_prompt = self._build_semgrep_prompt(ctx)
            file_path = ctx.get("file_path", "")
            code_snippet = ctx.get("code_snippet", "")
        else:
            system_prompt = SYSTEM_PROMPT_DEEP_ANALYSIS
            file_path = ctx.get("file_path", "")
            code_snippet = ctx.get("content", "")
            user_prompt = (
                f"## 분석 대상 파일\n파일 경로: {file_path}\n\n"
                f"## 소스코드\n```\n{code_snippet}\n```\n\n"
                f"위 코드에서 비즈니스 로직 결함을 분석하고, ISMS-P 규약 위반 여부도 함께 평가해주세요."
            )

        # ISMS-P RAG 적용
        if self.isms_kb:
            isms_ref = self.isms_kb.search_for_code_context(code_snippet[:500], file_path)
            if isms_ref:
                user_prompt += f"\n\n{isms_ref}"

        # LLM 파이프라인 호출
        prompt_tmpl = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", "{user_input}")
        ])
        chain = prompt_tmpl | self.structured_llm

        try:
            result: OutputModel = chain.invoke({"user_input": user_prompt})
            
            parsed_findings = []
            for f in result.findings:
                # None 값을 제거하고 Dict로 직렬화
                f_dict = f.model_dump(exclude_none=True)
                f_dict["source"] = "semgrep_verified" if ctype == "semgrep" else "deep_analysis"
                if ctype == "semgrep":
                    f_dict["original_file"] = file_path
                parsed_findings.append(f_dict)
                
            state["findings"] = parsed_findings
            
        except Exception as e:
            print(f"[!] LangChain LLM 추론 실패 ({file_path}): {e}")
            state["findings"] = []

        return state

    def analyze_semgrep_findings(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        for i, ctx in enumerate(contexts):
            print(f"  [→] Semgrep 결과 분석 중... ({i + 1}/{len(contexts)}) {ctx.get('file_path', '')}")
            initial_state: AnalysisState = {
                "context": ctx,
                "context_type": "semgrep",
                "findings": [],
                "needs_search": False,
                "search_query": ""
            }
            result_state = self.graph.invoke(initial_state)
            all_findings.extend(result_state.get("findings", []))
        return all_findings

    def analyze_critical_logic(self, critical_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        for i, ctx in enumerate(critical_files):
            content = ctx.get("content", "")
            if len(content) > 15000:
                print(f"  [→] 대용량 파일 스킵 (추후 분할 처리 구현 예정): {ctx.get('file_path', '')}")
                continue
                
            print(f"  [→] 핵심 로직 심층 분석 중... ({i + 1}/{len(critical_files)}) {ctx.get('file_path', '')}")
            initial_state: AnalysisState = {
                "context": ctx,
                "context_type": "deep_analysis",
                "findings": [],
                "needs_search": False,
                "search_query": ""
            }
            result_state = self.graph.invoke(initial_state)
            all_findings.extend(result_state.get("findings", []))
        return all_findings

    @staticmethod
    def _build_semgrep_prompt(ctx: Dict[str, Any]) -> str:
        return f"""## Semgrep 탐지 정보
- 규칙 ID: {ctx.get('rule_id', 'N/A')}
- 심각도: {ctx.get('severity', 'N/A')}
- 메시지: {ctx.get('message', 'N/A')}
- 파일: {ctx.get('file_path', 'N/A')}
- 위치: {ctx.get('start_line', '?')}~{ctx.get('end_line', '?')} 라인

## 코드 스니펫 (취약 라인은 >>> 마커로 표시됨)
```
{ctx.get('code_snippet', '')}
```

## 프로젝트 구조
```
{ctx.get('project_tree', '')}
```

위 Semgrep 탐지 결과가 오탐(False Positive)인지, 실제 취약점(True Positive)인지 검증하세요."""
