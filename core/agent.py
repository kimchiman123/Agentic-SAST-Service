"""
LangGraph 기반 AI 에이전트 심층 분석 모듈.
GPT 모델을 활용하여 Semgrep 결과 검증 및 비즈니스 로직 취약점을 파악하며,
향후 외부 도구(OSV, SerpAPI) 연동이 가능하도록 상태(StateGraph) 기반 워크플로우로 설계되었습니다.
"""
import os
import re
import json
import hashlib
import concurrent.futures
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

from core.isms_rag import ISMSKnowledgeBase
from core.state import AnalysisState
from core.tools.web_search import perform_web_search
from core.mcp_tools import create_scoped_tools
from core.path_policy import ScanPathPolicy


# ──────────────────────────────────────────────
#  1) Pydantic 모델 정의 (Structured Output)
# ──────────────────────────────────────────────

class DiscoveryModel(BaseModel):
    is_vulnerable_candidate: bool = Field(default=False, description="취약점 가능성 여부 (조금이라도 의심되면 True, 확실히 안전하면 False)")
    reason: str = Field(default="", description="원인 또는 해당 상태로 판정한 논리")

class FindingModel(BaseModel):
    rule_id: Optional[str] = Field(default=None, description="semgrep 규칙 ID")
    is_true_positive: bool = Field(default=True, description="오탐 여부")
    false_positive_reason: Optional[str] = Field(default=None, description="오탐일 경우 그 사유")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(default="INFO", description="심각도 수준")
    title: str = Field(default="제목 없음", description="취약점 제목 (한국어)")
    description: str = Field(default="", description="취약점 상세 설명 (한국어)")
    vulnerability_type: Literal["Code Injection", "IDOR", "Race Condition", "Logic Bypass", "Weak Password Hashing", "CSRF", "Supply Chain", "Other"] = Field(default="Other", description="취약점 분류 유형")
    file_path: Optional[str] = Field(default=None, description="취약점이 위치한 파일 경로")
    taint_analysis: Optional[str] = Field(default=None, description="데이터 흐름 추적 설명")
    exploit_scenario: str = Field(default="", description="상세 공격 시나리오")
    affected_code: str = Field(default="", description="취약한 코드 라인")
    evidence_start_line: Optional[int] = Field(default=None, ge=1, description="실제 파일에서 검증한 증거 시작 라인")
    evidence_end_line: Optional[int] = Field(default=None, ge=1, description="실제 파일에서 검증한 증거 종료 라인")
    remediation_code: str = Field(default="", description="수정된 안전한 코드")
    remediation_description: str = Field(default="", description="수정 방법 설명 (한국어)")
    isms_p_violation: Optional[str] = Field(default=None, description="ISMS-P 인증기준 조항 코드 (예: '2.5.3', '2.6.2') 또는 기술적 보안 가이드 항목 코드 (예: 'U-13', 'D-08'). 오직 해당 표준 코드/번호만 입력하십시오.")
    isms_p_description: Optional[str] = Field(default=None, description="위 매핑된 ISMS-P 조항에 따른 상세한 법적/기술적 위반 사항 및 보완 권고 설명 (한국어)")
    decision_tree: List[str] = Field(default_factory=list, description="취약점 판별부터 규정 매핑까지의 논리적 흐름 (최대 4~5단계의 간결한 문장 배열)")

class OutputModel(BaseModel):
    findings: List[FindingModel] = Field(default_factory=list)
    needs_external_search: bool = Field(default=False, description="의존성 취약점(SCA)에 대한 최신 PoC이나 제로데이 동향 파악, 최신 우회기법 등 웹 검색이 필요한 경우 True 설정")
    search_query: Optional[str] = Field(default=None, description="외부 검색 시 사용할 쿼리 (예: 'CVE-2023-xxxx exploit payload' 또는 'MongoDB NoSQL injection bypass cheat sheet')")


class EvidenceRequest(BaseModel):
    path_hint: str = Field(default="", description="분석 루트 기준 상대 경로")
    symbol: str = Field(default="", description="확인할 함수, 클래스 또는 변수")
    purpose: str = Field(default="", description="이 증거가 필요한 이유")


class AnalysisPlan(BaseModel):
    hypotheses: List[str] = Field(default_factory=list, max_length=6)
    evidence_requests: List[EvidenceRequest] = Field(default_factory=list, max_length=8)
    checks: List[str] = Field(default_factory=list, max_length=8)
    stop_conditions: List[str] = Field(default_factory=list, max_length=4)
    rag_query: str = Field(default="", max_length=500)


class VerificationResult(BaseModel):
    approved_indices: List[int] = Field(default_factory=list)
    rejected_reasons: List[str] = Field(default_factory=list)
    revision_required: bool = False


@dataclass(frozen=True)
class AnalysisLimits:
    max_workers: int = 2
    max_contexts: int = 50
    max_tool_rounds: int = 3
    max_tool_calls: int = 150
    max_llm_calls: int = 250
    max_findings: int = 200
    timeout_seconds: int = 1800
    recursion_limit: int = 24


class ScanBudget:
    """스캔 전체 호출량과 실행시간을 thread-safe하게 제한합니다."""

    def __init__(self, limits: AnalysisLimits) -> None:
        self.limits = limits
        self.started_at = time.monotonic()
        self.llm_calls = 0
        self.tool_calls = 0
        self.contexts = 0
        self.findings = 0
        self._lock = threading.Lock()

    def consume_llm(self, count: int = 1) -> bool:
        with self._lock:
            if time.monotonic() - self.started_at > self.limits.timeout_seconds:
                return False
            if self.llm_calls + count > self.limits.max_llm_calls:
                return False
            self.llm_calls += count
            return True

    def consume_tools(self, count: int) -> int:
        with self._lock:
            remaining = max(0, self.limits.max_tool_calls - self.tool_calls)
            accepted = min(max(0, count), remaining)
            self.tool_calls += accepted
            return accepted

    def consume_contexts(self, count: int) -> int:
        with self._lock:
            remaining = max(0, self.limits.max_contexts - self.contexts)
            accepted = min(max(0, count), remaining)
            self.contexts += accepted
            return accepted

    def consume_findings(self, count: int) -> int:
        with self._lock:
            remaining = max(0, self.limits.max_findings - self.findings)
            accepted = min(max(0, count), remaining)
            self.findings += accepted
            return accepted

    def stop_reason(self) -> str:
        if time.monotonic() - self.started_at > self.limits.timeout_seconds:
            return "scan timeout reached"
        if self.llm_calls >= self.limits.max_llm_calls:
            return "LLM call budget reached"
        if self.tool_calls >= self.limits.max_tool_calls:
            return "tool call budget reached"
        if self.contexts >= self.limits.max_contexts:
            return "context budget reached"
        if self.findings >= self.limits.max_findings:
            return "finding budget reached"
        return ""


# ──────────────────────────────────────────────
#  2) 시스템 프롬프트
# ──────────────────────────────────────────────

SYSTEM_PROMPT_SEMGREP_ANALYSIS = """[Role: Senior Application Security Engineer]
당신의 목표는 SAST(Semgrep) 결과를 검증하여 오탐(FP)을 제거하고, 실제 취약점(TP)에 대한 완벽한 수정안을 제시하는 것입니다.

[지시사항]
1. 오탐(FP) 판별: 제공된 코드 문맥 상 공격자의 제어(User-Controlled Input)가 불가하거나 방어 로직이 있다면 완벽한 오탐으로 처리하세요.
2. 실제 취약점(TP) 판별: 소스(입력)부터 싱크(실행부)까지 경로 증명, 페이로드 작성, 방어 코드 적용 방안을 준비하세요.
3. 코드 문맥이 부족하다면 추측하지 말고 제공된 `read_source` 로 해당 라인을 확인하세요. (최대 1~2회 제한)
4. 승인된 조사 계획을 따르고, 도구 결과에서 확인한 파일·라인 근거만 간결하게 기록하세요. 숨은 사고과정이나 장문의 Chain-of-Thought를 출력하지 마세요.
5. (중요) ISMS-P 규정 위반을 설명할 때, 가능하다면 제공된 RAG 문맥 내의 구체적인 기술적 취약점 코드(예: U-01 등)나 OT 제로트러스트 보안 원칙을 함께 인용하여 보고서를 전문적으로 작성하세요.
6. (중요) 심각도가 LOW나 INFO인 사소한 건은 토큰 및 리포트 공간을 아끼기 위해 복잡한 분석(Taint Analysis, 코드 시나리오 등)을 생략하고, 직관적으로 5~6줄 이내로 간단하게 핵심만 언급하고 넘어가세요.
7. 분석 완료 후 `decision_tree`에는 검증 가능한 근거 요약만 기록하세요. (예: ["사용자 입력 위치 확인", "검증 부재 라인 확인", "SQL 실행 위치 확인", "ISMS-P 2.6.2 매핑"])
"""

SYSTEM_PROMPT_DEEP_ANALYSIS = """[Role: Senior Application Security Engineer]
당신의 목표는 정규식 위주의 SAST가 잡지 못하는 '비즈니스 로직 및 아키텍처 결함(Business Logic Flaws)'을 찾는 것입니다.

[주요 탐지 타겟]
1. Broken Access Control (IDOR, 권한 우회)
2. Race Condition (동시성 처리 오류)
3. Input Logic Bypass (예상치 못한 값, 오버플로우 우회)
4. Hardcoded Secrets (DB, API Key 등)

[지시사항 - 비용 및 보안 밸런스 최적화]
1. (Fail Fast): 코드를 검토한 후 실제 Exploit 가능한 로직 결함이 보이지 않는다면, 억지로 취약점을 지어내지 마세요. 불필요한 도구 호출을 멈추고 빈 상태로 즉시 분석을 종료하세요.
2. (Data Flow 추적): 취약점이 의심된다면 Source(사용자 입력)부터 Sink(실제 동작)까지의 오염(Taint) 경로를 명확하게 추적하여 오탐을 방지하세요.
3. (Exploit 가능성): 방어 코드(검증 로직)가 존재하여 공격 시나리오가 성립하지 않으면 무시하세요.
4. (전문성): ISMS-P 규정 위반을 설명할 때, RAG 문맥 내의 구체적인 취약점 코드나 제로트러스트 원칙을 인용하세요.
5. (근거 요약): `decision_tree`에는 파일·라인에서 확인 가능한 근거를 순서대로 요약하세요. 숨은 사고과정이나 장문의 Chain-of-Thought는 출력하지 마세요.
"""


# ──────────────────────────────────────────────
#  3) LangGraph 기반 Agent 클래스
# ──────────────────────────────────────────────

class OpenAIAgent:
    """
    Phase 3: LangGraph + 외부 검색(SerpAPI) 라우팅 기능을 결합한 완전 자율형 Agent.
    """

    MODEL_NAME = "gpt-5.4-mini"

    def __init__(
        self,
        isms_kb: Optional[ISMSKnowledgeBase] = None,
        osv_vulns: Optional[List[Dict[str, Any]]] = None,
        *,
        target_root: str,
        api_key: Optional[str] = None,
        limits: Optional[AnalysisLimits] = None,
        enable_web_search: bool = False,
    ) -> None:
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("[!] OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

        # Discovery Agent (가볍고 빠른 필터링) - Stage 2
        self.nano_llm = ChatOpenAI(
            model="gpt-5.4-nano", api_key=api_key, temperature=0.0,
            request_timeout=60, max_retries=2,
        )
        self.discovery_llm = self.nano_llm.with_structured_output(DiscoveryModel)
        self.planner_llm = self.nano_llm.with_structured_output(AnalysisPlan)
        self.verifier_llm = self.nano_llm.with_structured_output(VerificationResult)
        
        # Analysis Agent (심층 분석 및 Tool Calling) - Stage 3
        self.mini_llm = ChatOpenAI(
            model="gpt-5.4-mini", api_key=api_key, temperature=0.1,
            request_timeout=90, max_retries=2,
        )
        self.structured_llm = self.mini_llm.with_structured_output(OutputModel)
        
        # MCP 도구 목록 바인딩 (분석은 Mini가 수행해야 함)
        self.path_policy = ScanPathPolicy(target_root)
        self.tools = create_scoped_tools(self.path_policy)
        self.mini_llm_with_tools = self.mini_llm.bind_tools(self.tools)
        
        self.isms_kb = isms_kb
        self.osv_vulns = osv_vulns or []
        self.limits = limits or AnalysisLimits()
        self.budget = ScanBudget(self.limits)
        self.enable_web_search = enable_web_search
        self.graph = self._build_graph()

    def _build_graph(self):
        """LangGraph 워크플로우를 조립합니다."""
        workflow = StateGraph(AnalysisState)
        
        # 노드 선언
        workflow.add_node("discovery_node", self._discovery_node)
        workflow.add_node("plan_node", self._plan_node)
        workflow.add_node("analyze_node", self._analyze_node)
        workflow.add_node("mcp_tools", ToolNode(self.tools))
        workflow.add_node("record_tool_round", self._record_tool_round_node)
        workflow.add_node("search_node", self._search_node)
        workflow.add_node("final_report_node", self._final_report_node)
        workflow.add_node("verify_node", self._verify_node)
        workflow.add_node("revise_node", self._revise_node)
        
        # 제어 흐름(Edge) 선언
        workflow.add_edge(START, "discovery_node")
        workflow.add_conditional_edges("discovery_node", self._should_analyze, {"plan": "plan_node", "end": END})
        workflow.add_edge("plan_node", "analyze_node")
        
        # Tool Node 루프 조건
        workflow.add_conditional_edges("analyze_node", self._should_continue_tools, {"tools": "mcp_tools", "final_report": "final_report_node"})
        workflow.add_edge("mcp_tools", "record_tool_round")
        workflow.add_edge("record_tool_round", "analyze_node")
        
        # 리포트 노드 -> 서치 (있으면) -> 리턴
        workflow.add_conditional_edges("final_report_node", self._should_search, {"search": "search_node", "verify": "verify_node"})
        workflow.add_edge("search_node", "final_report_node")
        workflow.add_conditional_edges("verify_node", self._should_revise, {"revise": "revise_node", "end": END})
        workflow.add_edge("revise_node", "verify_node")
        
        return workflow.compile()
        
    def _should_analyze(self, state: AnalysisState) -> str:
        if state.get("is_vulnerable_candidate"):
            return "plan"
        return "end"

    def _should_continue_tools(self, state: AnalysisState) -> str:
        messages = state.get("messages", [])
        if not messages:
            return "final_report"
        last_message = messages[-1]
        
        if getattr(last_message, "tool_calls", None) and state.get("tool_rounds", 0) < state.get("max_tool_rounds", self.limits.max_tool_rounds):
            return "tools"
        return "final_report"

    def _should_search(self, state: AnalysisState) -> str:
        """라우터 로직: 검색 필요 시 검색 노드로 회귀, 아니면 종료."""
        if self.enable_web_search and state.get("needs_search") and state.get("web_search_count", 0) < 1:
            return "search"
        return "verify"

    def _should_revise(self, state: AnalysisState) -> str:
        verification = state.get("verification", {})
        if verification.get("revision_required") and state.get("revision_count", 0) < 1:
            return "revise"
        return "end"

    def _search_node(self, state: AnalysisState) -> dict:
        """실제 웹 검색을 수행하고 결과를 상태(State)에 주입합니다."""
        query = state.get("search_query", "")
        query = query.strip()
        known_package_match = any(
            len(package) >= 3
            and re.search(
                rf"(?<![A-Za-z0-9@._/+:-]){re.escape(package)}(?![A-Za-z0-9@._/+:-])",
                query,
                re.IGNORECASE,
            )
            for package in (str(v.get("package", "")).strip() for v in self.osv_vulns)
            if package
        )
        allowed_query = bool(
            3 <= len(query) <= 120
            and "\n" not in query
            and re.fullmatch(r"[A-Za-z0-9@._:/+ -]+", query)
            and (re.search(r"\b(?:CVE|CWE)-\d+", query, re.IGNORECASE) or known_package_match)
        )
        if not allowed_query or self.budget.consume_tools(1) != 1:
            return {"search_result": "", "web_search_count": 1, "needs_search": False}
        print(f"  [검색] 외부 보안 검색 실행 중 (query length: {len(query)})")
        try:
            res = perform_web_search(query)
        except Exception as e:
            print(f"  [!] 외부 검색 오류: {type(e).__name__}")
            res = "검색 실패"
        
        return {
            "search_result": res,
            "web_search_count": state.get("web_search_count", 0) + 1,
            "needs_search": False
        }

    def _plan_node(self, state: AnalysisState) -> dict:
        """도구 권한이 없는 Planner가 감사 가능한 조사 계획만 작성합니다."""
        ctx = state.get("context", {})
        fallback = AnalysisPlan(
            hypotheses=["제공된 코드에서 source-to-sink 보안 경로를 확인한다."],
            evidence_requests=[EvidenceRequest(path_hint=ctx.get("file_path", ""), purpose="분석 대상 코드 확인")],
            checks=["입력 통제 여부", "방어 로직 존재 여부", "실제 악용 가능성"],
            stop_conditions=["실제 코드 근거가 없으면 finding을 생성하지 않는다."],
            rag_query=ctx.get("message", "")[:500],
        )
        if not self.budget.consume_llm():
            return {"analysis_plan": fallback.model_dump(), "phase": "planned", "stop_reason": self.budget.stop_reason()}

        prompt = (
            "다음 코드 보안 분석을 위한 짧은 조사 계획을 작성하라. 숨은 사고과정은 쓰지 말고 "
            "가설, 필요한 파일 근거, 확인 항목, 중단 조건만 구조화하라.\n\n"
            f"분석 유형: {state.get('context_type', '')}\n대상: {ctx.get('file_path', '')}\n"
            f"탐지 메시지: {ctx.get('message', '')}\n코드:\n{ctx.get('code_snippet', ctx.get('content', ''))[:4000]}"
        )
        try:
            plan: AnalysisPlan = self.planner_llm.invoke([SystemMessage(content="너는 read-only 보안 분석 Planner다. 도구를 사용할 수 없다."), HumanMessage(content=prompt)])
        except Exception as exc:
            return {"analysis_plan": fallback.model_dump(), "phase": "planned", "errors": [f"planner fallback: {type(exc).__name__}"]}

        safe_requests = []
        for request in plan.evidence_requests:
            if not request.path_hint:
                continue
            try:
                request.path_hint = self.path_policy.safe_relative_path(request.path_hint)
            except Exception:
                continue
            safe_requests.append(request)
        plan.evidence_requests = safe_requests
        return {"analysis_plan": plan.model_dump(), "phase": "planned"}

    @staticmethod
    def _record_tool_round_node(state: AnalysisState) -> dict:
        return {"tool_rounds": state.get("tool_rounds", 0) + 1, "phase": "executing"}

    def _discovery_node(self, state: AnalysisState) -> dict:
        """Stage 2: Discovery Agent (nano 모델) 가벼운 사전 필터링"""
        ctx = state["context"]
        ctype = state["context_type"]
        
        # 간단한 프롬프트로 의심 여부 판독
        if ctx.get("lazy_load"):
            print(f"  [Lazy] 대용량 파일이므로 단계 2 필터링을 생략하고 심층 분석으로 직행: {ctx.get('file_path', '')}")
            return {"is_vulnerable_candidate": True}
            
        if ctype == "semgrep":
            prompt = f"Semgrep 탐지결과: {ctx.get('message', '')}\n파일: {ctx.get('file_path', '')}\n코드 스니펫:\n{ctx.get('code_snippet', '')}"
        else:
            prompt = f"심층 분석 핵심파일:\n{ctx.get('content', '')[:1000]}..."
            
        sys_prompt = """너는 보안 분석 예비 검토자(Discovery Agent)다.
전달받은 코드를 분석하여 보안상 '위험 가능성'이 있는지 1차적으로 판단하라.

[안전 판정 기준 (false 반환)]
다음 중 하나라도 해당되며, 인증/DB/파일처리와 무관하다면 무조건 `is_vulnerable_candidate: false`를 반환하라.
1. 순수 UI, 프론트엔드 렌더링 또는 DOM 조작 코드
2. 문자열 가공, 수학 계산, 난수 생성, 정렬 등 단순 유틸리티 로직
3. 더미 데이터, 하드코딩된 에러 메시지, 상수 파일

[위험 판정 기준 (true 반환)]
다음 단어가 포함되어 있거나 관련 로직이 1줄이라도 있다면 반드시 `is_vulnerable_candidate: true`를 반환하라.
1. 인증/인가 (JWT, session, password, login, auth, role, token)
2. 외부 데이터 처리 (eval, request, body, sql, query, fs)
3. 금융/결제 등 비즈니스 중요 상태 (balance, amount, pay, transfer)
"""
        
        if not self.budget.consume_llm():
            return {"is_vulnerable_candidate": False, "stop_reason": self.budget.stop_reason()}
        try:
            res: DiscoveryModel = self.discovery_llm.invoke([
                SystemMessage(content=sys_prompt),
                HumanMessage(content=prompt)
            ])
            if not res.is_vulnerable_candidate:
                print("  [Skip] 단계 2: 의심 없음으로 스킵됨")
            return {"is_vulnerable_candidate": res.is_vulnerable_candidate}
        except Exception as e:
            # 예외 발생 시 안전을 고려하여 무조건 분석 단계를 통과
            return {"is_vulnerable_candidate": True}

    def _analyze_node(self, state: AnalysisState) -> dict:
        """승인된 계획 범위에서만 실행하고 도구 호출을 코드로 제한합니다."""
        ctx = state["context"]
        ctype = state["context_type"]
        messages = state.get("messages", [])
        
        new_messages = []
        if not messages:
            # 최초 메시지 구성
            if ctype == "semgrep":
                system_prompt = SYSTEM_PROMPT_SEMGREP_ANALYSIS
                user_prompt = self._build_semgrep_prompt(ctx)
            else:
                system_prompt = SYSTEM_PROMPT_DEEP_ANALYSIS
                file_path = ctx.get("file_path", "")
                code_snippet = ctx.get("content", "")
                
                # FIX 1: LLM이 실제로 코드를 보고 분석할 수 있도록 컨텍스트를 프롬프트에 주입
                user_prompt = (
                    f"## 분석 대상 파일\n파일 경로: {file_path}\n\n"
                    f"## 제공된 코드 컨텍스트\n```\n{code_snippet}\n```\n\n"
                    f"위 코드를 주시하여 프로젝트의 비즈니스 로직 결함을 분석하세요. 제공된 코드로 불충분할 경우 도구를 호출하세요."
                )
            
            plan_json = json.dumps(state.get("analysis_plan", {}), ensure_ascii=False)
            new_messages.append(SystemMessage(content=system_prompt))
            new_messages.append(HumanMessage(content=f"{user_prompt}\n\n## 승인된 조사 계획\n{plan_json}"))

        if not self.budget.consume_llm():
            return {
                "messages": new_messages + [AIMessage(content="전역 분석 예산에 도달하여 추가 실행을 중단합니다.")],
                "phase": "budget_exhausted",
                "stop_reason": self.budget.stop_reason(),
            }

        try:
            invoke_messages = messages + new_messages
            if state.get("tool_rounds", 0) >= state.get("max_tool_rounds", self.limits.max_tool_rounds):
                invoke_messages = invoke_messages + [HumanMessage(content="도구 예산이 끝났습니다. 현재 근거만 요약하고 추가 도구를 호출하지 마세요.")]
                response = self.mini_llm.invoke(invoke_messages)
            else:
                response = self.mini_llm_with_tools.invoke(invoke_messages)

            proposed_calls = list(getattr(response, "tool_calls", None) or [])
            if proposed_calls:
                accepted = self.budget.consume_tools(min(2, len(proposed_calls)))
                if accepted:
                    response = AIMessage(content=response.content or "", tool_calls=proposed_calls[:accepted])
                else:
                    response = AIMessage(content="전역 도구 예산에 도달했습니다. 현재 근거만으로 분석을 종료합니다.")
            new_messages.append(response)
        except Exception as e:
            print(f"  [!] Analysis LLM 오류: {type(e).__name__}")

        return {"messages": new_messages, "phase": "executing"}

    def _final_report_node(self, state: AnalysisState) -> dict:
        """분석(Tool Calling) 완료 후 최종 리포트를 Pydantic으로 산출"""
        messages = state.get("messages", [])
        
        # 분석 도구 루프 이후 근거 기반 후보 finding 생성
        final_prompt = (
            "지금까지의 탐색 과정과 결과를 종합하여, 최종 취약점 보고서를 작성해주세요.\n"
            "취약점이 발견되었다면 findings 리스트에 상세히 담으세요.\n"
            "각 취약점에 실제 상대 파일 경로, 확인한 코드, 정확한 evidence_start_line/evidence_end_line을 포함하고, "
            "decision_tree에는 검증 가능한 근거를 3~5단계로 요약하세요.\n"
            "**반드시 JSON 형식으로만 응답해야 합니다.**\n"
        )
        
        # 외부 컨텍스트 주입 (RAG)
        extra_context = ""
        # 웹 검색 결과가 존재한다면 주입 (2번째 사이클)
        search_res = state.get("search_result", "")
        if search_res:
            extra_context += f"## 최신 웹 검색 결과 데이터:\n{search_res}\n\n"
        
        # OSV 컨텍스트 추가
        if self.osv_vulns:
            extra_context += "## SCA 외부 라이브러리 취약점 내역\n"
            for v in self.osv_vulns:
                extra_context += f"- 패키지: {v['package']} v{v['version']} | {v['cve_id']}\n"
        
        # ISMS-P 추가
        if self.isms_kb:
            query_text = state.get("analysis_plan", {}).get("rag_query", "")[:500]
            if not query_text:
                ctx = state.get("context", {})
                query_text = ctx.get("code_snippet", ctx.get("content", ""))[:500]
                
            file_path = state.get("context", {}).get("file_path", "")
            isms_ref = self.isms_kb.search_for_code_context(query_text, file_path)
            
            if isms_ref:
                extra_context += f"## 관련 ISMS-P 지침\n{isms_ref}\n"

        if extra_context:
            final_prompt += "\n" + extra_context
            
        invoke_messages = messages + [HumanMessage(content=final_prompt)]
        
        if not self.budget.consume_llm():
            return {
                "candidate_findings": [], "findings": [], "needs_search": False,
                "phase": "budget_exhausted", "stop_reason": self.budget.stop_reason(),
            }

        try:
            # 1단계: structured_output 시도
            try:
                result: OutputModel = self.structured_llm.invoke(invoke_messages)
            except Exception:
                # 2단계: 실패 시 일반 텍스트 호출 후 수동 파싱 (Robust Parsing)
                if not self.budget.consume_llm():
                    raise RuntimeError(self.budget.stop_reason())
                raw_response = self.mini_llm.invoke(invoke_messages)
                content = raw_response.content
                # JSON 블록만 추출 (백틱 제거 및 슬롭 방지)
                json_match = re.search(r"({.*})", content, re.DOTALL)
                if json_match:
                    content = json_match.group(1)
                else:
                    # 앞뒤 공백 및 마크다운 표시 제거
                    content = content.strip().replace("```json", "").replace("```", "").strip()
                
                result = OutputModel.model_validate_json(content)
            
            parsed_findings = []
            for f in result.findings:
                f_dict = f.model_dump(exclude_none=True)
                # 소스 정보 강제 주입
                f_dict["source"] = "semgrep_verified" if state["context_type"] == "semgrep" else "deep_analysis"
                if state["context_type"] == "semgrep":
                    f_dict["original_file"] = state["context"].get("file_path", "")
                evidence_context = {
                    "file_path": (
                        state["context"].get("file_path", "")
                        if state["context_type"] == "semgrep"
                        else f_dict.get("file_path", "")
                    ),
                    "start_line": f_dict.get("evidence_start_line") or (
                        state["context"].get("start_line") if state["context_type"] == "semgrep" else None
                    ),
                    "end_line": f_dict.get("evidence_end_line") or (
                        state["context"].get("end_line") if state["context_type"] == "semgrep" else None
                    ),
                }
                server_evidence = self._evidence_from_context(evidence_context)
                if server_evidence:
                    f_dict["_evidence"] = server_evidence
                parsed_findings.append(f_dict)
                
            return {
                "candidate_findings": parsed_findings,
                "needs_search": result.needs_external_search,
                "search_query": result.search_query or "",
                "phase": "synthesized",
            }
            
        except Exception as e:
            print(f"  [!] 최종 리포트 작성/파싱 실패: {type(e).__name__}")
            return {
                "candidate_findings": [],
                "findings": [],
                "needs_search": False,
                "search_query": "",
                "phase": "synthesis_failed",
            }

    def _verify_node(self, state: AnalysisState) -> dict:
        """결정적 근거 규칙과 독립 LLM 검토로 후보 finding을 승인합니다."""
        candidates = state.get("candidate_findings", [])[: self.limits.max_findings]
        deterministic_indices = []
        deterministic_rejections = []
        for index, finding in enumerate(candidates):
            file_path = finding.get("original_file") or finding.get("file_path")
            affected_code = self._canonical_evidence_snippet(finding.get("affected_code", ""))
            has_location = False
            evidence_matches = False
            try:
                evidence_file = self.path_policy.validate_file(file_path)
                finding["file_path"] = self.path_policy.safe_relative_path(evidence_file, expected_type="file")
                has_location = True
                server_evidence = finding.get("_evidence")
                if server_evidence:
                    evidence_matches = self._validate_server_evidence(server_evidence, finding["file_path"])
                elif len(affected_code) >= 8 and evidence_file.stat().st_size <= 2_000_000:
                    actual = evidence_file.read_text(encoding="utf-8", errors="ignore")
                    normalized_actual = " ".join(actual.split())
                    normalized_evidence = " ".join(affected_code.split())
                    evidence_matches = normalized_evidence in normalized_actual
            except Exception:
                pass
            if not finding.get("is_true_positive", True):
                deterministic_rejections.append(f"{index}: false positive")
            elif not (has_location and evidence_matches):
                deterministic_rejections.append(f"{index}: finding without matching file evidence")
            else:
                deterministic_indices.append(index)

        verification = VerificationResult(
            approved_indices=deterministic_indices,
            rejected_reasons=deterministic_rejections,
            revision_required=bool(deterministic_rejections),
        )
        if deterministic_indices and self.budget.consume_llm():
            evidence_messages = []
            for message in state.get("messages", [])[-8:]:
                content = getattr(message, "content", "")
                if content:
                    evidence_messages.append(str(content)[:2000])
            prompt = (
                "후보 취약점이 제공된 계획과 코드 근거로 입증되는지 독립 검증하라. "
                "승인할 후보의 원래 배열 index만 approved_indices에 넣고, 근거 부족은 거부하라.\n"
                f"계획: {json.dumps(state.get('analysis_plan', {}), ensure_ascii=False)}\n"
                f"원본 context: {json.dumps(state.get('context', {}), ensure_ascii=False)[:5000]}\n"
                f"수집 증거: {json.dumps(evidence_messages, ensure_ascii=False)[:8000]}\n"
                f"후보: {json.dumps(candidates, ensure_ascii=False)[:12000]}"
            )
            try:
                llm_verification: VerificationResult = self.verifier_llm.invoke([
                    SystemMessage(content="너는 도구가 없는 독립 Evidence Verifier다."),
                    HumanMessage(content=prompt),
                ])
                allowed = set(deterministic_indices)
                verification.approved_indices = list(dict.fromkeys(
                    i for i in llm_verification.approved_indices if i in allowed
                ))
                verification.rejected_reasons.extend(llm_verification.rejected_reasons)
                verification.revision_required = llm_verification.revision_required or len(verification.approved_indices) < len(candidates)
            except Exception as exc:
                verification.rejected_reasons.append(f"verifier fallback: {type(exc).__name__}")

        approved = []
        for i in verification.approved_indices:
            if 0 <= i < len(candidates):
                public_finding = dict(candidates[i])
                public_finding.pop("_evidence", None)
                approved.append(public_finding)
        return {
            "findings": approved[: self.limits.max_findings],
            "verification": verification.model_dump(),
            "phase": "verified",
        }

    def _evidence_from_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Semgrep 위치에서 변경 불가능한 서버 측 증거 레코드를 만듭니다."""
        try:
            path = self.path_policy.safe_relative_path(context.get("file_path", ""), expected_type="file")
            start = int(context.get("start_line", 0))
            end = int(context.get("end_line", 0))
            if start < 1 or end < start or end - start > 300:
                return {}
            source_file = self.path_policy.validate_file(path)
            lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            if start > len(lines):
                return {}
            end = min(end, len(lines))
            snippet = "\n".join(lines[start - 1:end]).strip()
            if len(snippet) < 8:
                return {}
            return {
                "path": path,
                "start_line": start,
                "end_line": end,
                "snippet": snippet,
                "sha256": hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
            }
        except (OSError, TypeError, ValueError):
            return {}

    def _validate_server_evidence(self, evidence: Any, expected_path: str) -> bool:
        if not isinstance(evidence, dict) or evidence.get("path") != expected_path:
            return False
        rebuilt = self._evidence_from_context({
            "file_path": evidence.get("path"),
            "start_line": evidence.get("start_line"),
            "end_line": evidence.get("end_line"),
        })
        return bool(
            rebuilt
            and rebuilt.get("snippet") == evidence.get("snippet")
            and rebuilt.get("sha256") == evidence.get("sha256")
        )

    @staticmethod
    def _canonical_evidence_snippet(value: Any) -> str:
        """코드펜스와 줄번호 표기만 제거하고 실제 코드 내용은 보존합니다."""
        snippet = str(value or "").strip()
        fenced = re.fullmatch(r"```[^\n`]*\n([\s\S]*?)\n?```", snippet)
        if fenced:
            snippet = fenced.group(1)
        cleaned_lines = []
        for line in snippet.splitlines():
            cleaned_lines.append(re.sub(r"^\s*(?:L?\d+(?:\s*[~-]\s*\d+)?\s*[:|]\s*)", "", line))
        return "\n".join(cleaned_lines).strip()

    def _revise_node(self, state: AnalysisState) -> dict:
        """Verifier 피드백을 반영한 후보 수정은 최대 한 번만 허용합니다."""
        if not self.budget.consume_llm():
            return {"revision_count": 1, "phase": "revision_skipped", "stop_reason": self.budget.stop_reason()}
        prompt = (
            "Verifier 피드백에 따라 설명과 심각도만 교정하라. 파일 경로와 affected_code는 절대 "
            "변경하거나 새로 만들지 말고, 입증 불가능한 항목은 제거하라. JSON schema를 유지하라.\n"
            f"후보: {json.dumps(state.get('candidate_findings', []), ensure_ascii=False)[:12000]}\n"
            f"검증: {json.dumps(state.get('verification', {}), ensure_ascii=False)}"
        )
        try:
            revised: OutputModel = self.structured_llm.invoke([
                SystemMessage(content="너는 근거를 생성할 수 없는 제한된 Report Reviser다."),
                HumanMessage(content=prompt),
            ])
            originals = defaultdict(deque)
            for item in state.get("candidate_findings", []):
                key = (
                    str(item.get("original_file") or item.get("file_path") or ""),
                    self._canonical_evidence_snippet(item.get("affected_code", "")),
                )
                originals[key].append(item)
            candidates = []
            for finding in revised.findings:
                finding_dict = finding.model_dump(exclude_none=True)
                key = (
                    str(finding_dict.get("file_path", "")),
                    self._canonical_evidence_snippet(finding_dict.get("affected_code", "")),
                )
                matches = originals.get(key)
                if not matches:
                    continue
                original = matches.popleft()
                for immutable_key in (
                    "file_path", "original_file", "affected_code", "taint_analysis",
                    "source", "is_true_positive", "vulnerability_type", "rule_id", "_evidence",
                    "evidence_start_line", "evidence_end_line",
                ):
                    if immutable_key in original:
                        finding_dict[immutable_key] = original[immutable_key]
                candidates.append(finding_dict)
        except Exception:
            source_candidates = state.get("candidate_findings", [])
            approved_indices = state.get("verification", {}).get("approved_indices", [])
            candidates = [
                source_candidates[index]
                for index in approved_indices
                if isinstance(index, int) and 0 <= index < len(source_candidates)
            ]
        return {"candidate_findings": candidates, "revision_count": 1, "phase": "revised"}

    def analyze_semgrep_findings(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        reserved_share = max(1, self.limits.max_contexts // 2)
        contexts = contexts[: self.budget.consume_contexts(min(len(contexts), reserved_share))]
        
        def _process(ctx, idx):
            import time
            print(f"  [→] Semgrep 결과 검증 중... ({idx + 1}/{len(contexts)}) {ctx.get('file_path', '')}")
            initial_state: AnalysisState = {
                "context": ctx,
                "context_type": "semgrep",
                "is_vulnerable_candidate": False,
                "findings": [],
                "needs_search": False,
                "search_query": "",
                "search_result": "",
                "iteration": 0,
                "web_search_count": 0,
                "tool_rounds": 0,
                "max_tool_rounds": self.limits.max_tool_rounds,
                "revision_count": 0,
                "messages": [],
                "errors": [],
            }
            # FIX 2: Rate Limit(429) 대비 Exponential Backoff 재시도 로직
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result_state = self.graph.invoke(initial_state, config={"recursion_limit": self.limits.recursion_limit})
                    return result_state.get("findings", [])
                except Exception as e:
                    if "429" in str(e) or "RateLimit" in str(e):
                        wait_time = 2 ** attempt
                        print(f"  [!] Rate Limit 발생. {wait_time}초 후 재시도... ({attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        print(f"  [!] Semgrep 검증 스레드 예외 발생: {type(e).__name__}")
                        break
            return []
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.limits.max_workers) as executor:
            futures = [executor.submit(_process, ctx, i) for i, ctx in enumerate(contexts)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    batch = future.result()
                    all_findings.extend(batch[: self.budget.consume_findings(len(batch))])
                except Exception as e:
                    print(f"  [!] Semgrep 검증 스레드 오류: {type(e).__name__}")
                    
        return all_findings[: self.limits.max_findings]

    def analyze_critical_logic(self, critical_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        critical_files = critical_files[: self.budget.consume_contexts(len(critical_files))]
        
        def _process(ctx, idx):
            content = ctx.get("content", "")
            
            if len(content) > 15000:
                print(f"  [→] 대용량 파일 Lazy Loading 전환: {ctx.get('file_path', '')}")
                ctx["lazy_load"] = True
                
                # 상단 50줄 + 함수/클래스 시그니처 추출
                lines = content.splitlines()
                header = "\n".join(lines[:50])
                
                signatures = []
                sig_pattern = re.compile(r'^\s*(def |class |function |async function |const \w+ = \(.*?\) =>|export const |export function |type |interface |func |public |private |protected )')
                for i, line in enumerate(lines):
                    if sig_pattern.match(line):
                        signatures.append(f"Line {str(i+1).ljust(4)}: {line.strip()[:100]}")
                        
                sig_text = "\n".join(signatures)
                if not sig_text:
                    sig_text = "감지된 함수/클래스 시그니처가 없습니다."
                
                ctx["content"] = (
                    "[SYSTEM] 이 파일은 대용량 파일(15,000자 초과)이므로 전체 코드가 생략되었습니다.\n"
                    "아래 제공된 '파일 상단 내용'과 '구조 힌트(함수/클래스 목록)'를 참조하세요.\n"
                    "당신은 `read_source(file_path, start_line, end_line)` 도구를 반복 사용하여 의심되는 부분을 직접 읽어보아야 합니다.\n"
                    "추측성 취약점 보고는 금지되며, 반드시 도구로 실제 코드를 확인 후 심층 분석(CoT)을 진행하세요.\n\n"
                    "## 1. 파일 상단 50줄 (Header & Imports)\n"
                    "```\n" + header + "\n```\n\n"
                    "## 2. 감지된 함수/클래스 목록 (힌트 - 줄 번호 참조)\n"
                    "```\n" + sig_text + "\n```"
                )

            print(f"  [→] 핵심 로직 심층 분석 중... ({idx + 1}/{len(critical_files)}) {ctx.get('file_path', '')}")
            initial_state: AnalysisState = {
                "context": ctx,
                "context_type": "deep_analysis",
                "is_vulnerable_candidate": False,
                "findings": [],
                "needs_search": False,
                "search_query": "",
                "search_result": "",
                "iteration": 0,
                "web_search_count": 0,
                "tool_rounds": 0,
                "max_tool_rounds": self.limits.max_tool_rounds,
                "revision_count": 0,
                "messages": [],
                "errors": [],
            }
            
            # FIX 2: Rate Limit(429) 대비 Exponential Backoff 재시도 로직
            import time
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result_state = self.graph.invoke(initial_state, config={"recursion_limit": self.limits.recursion_limit})
                    return result_state.get("findings", [])
                except Exception as e:
                    if "429" in str(e) or "RateLimit" in str(e):
                        wait_time = 2 ** attempt
                        print(f"  [!] Rate Limit 발생. {wait_time}초 후 심층분석 재시도... ({attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        print(f"  [!] 심층 분석 스레드 예외 발생: {type(e).__name__}")
                        break
            return []
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.limits.max_workers) as executor:
            futures = [executor.submit(_process, ctx, i) for i, ctx in enumerate(critical_files)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    batch = future.result()
                    all_findings.extend(batch[: self.budget.consume_findings(len(batch))])
                except Exception as e:
                    print(f"  [!] 심층 분석 스레드 오류: {type(e).__name__}")
                    
        return all_findings[: self.limits.max_findings]

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
