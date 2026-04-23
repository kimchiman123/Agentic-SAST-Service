"""
LangGraph 기반 AI 에이전트 심층 분석 모듈.
GPT 모델을 활용하여 Semgrep 결과 검증 및 비즈니스 로직 취약점을 파악하며,
향후 외부 도구(OSV, SerpAPI) 연동이 가능하도록 상태(StateGraph) 기반 워크플로우로 설계되었습니다.
"""
import os
import concurrent.futures
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

from core.isms_rag import ISMSKnowledgeBase
from core.state import AnalysisState
from core.tools.web_search import perform_web_search
from core.mcp_tools import read_source, search_code


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
    needs_external_search: bool = Field(default=False, description="의존성 취약점(SCA)에 대한 최신 PoC이나 제로데이 동향 파악, 최신 우회기법 등 웹 검색이 필요한 경우 True 설정")
    search_query: Optional[str] = Field(default=None, description="외부 검색 시 사용할 쿼리 (예: 'CVE-2023-xxxx exploit payload' 또는 'MongoDB NoSQL injection bypass cheat sheet')")


# ──────────────────────────────────────────────
#  2) 시스템 프롬프트
# ──────────────────────────────────────────────

SYSTEM_PROMPT_SEMGREP_ANALYSIS = """[Role: Senior Application Security Engineer]
당신의 목표는 SAST(Semgrep) 결과를 검증하여 오탐(FP)을 제거하고, 실제 취약점(TP)에 대한 완벽한 수정안을 제시하는 것입니다.

[지시사항]
1. 오탐(FP) 판별: 제공된 코드 문맥 상 공격자의 제어(User-Controlled Input)가 불가하거나 방어 로직이 있다면 완벽한 오탐으로 처리하세요.
2. 실제 취약점(TP) 판별: 소스(입력)부터 싱크(실행부)까지 경로 증명, 페이로드 작성, 방어 코드 적용 방안을 준비하세요.
3. 코드 문맥이 부족하다면 추측하지 말고 제공된 `read_source` 로 해당 라인을 확인하세요. (최대 1~2회 제한)
4. (중요) 도구를 호출하거나 분석을 최종 완료하기 전, 반드시 해당 취약점에 대한 논리적인 추론 과정(Chain-of-Thought)을 먼저 텍스트로 길고 자세히 풀어서 출력하세요.
6. (중요) 심각도가 LOW나 INFO인 사소한 건은 토큰 및 리포트 공간을 아끼기 위해 복잡한 분석(Taint Analysis, 코드 시나리오 등)을 생략하고, 직관적으로 5~6줄 이내로 간단하게 핵심만 언급하고 넘어가세요.
"""

SYSTEM_PROMPT_DEEP_ANALYSIS = """[Role: Senior Application Security Engineer]
당신의 목표는 정규식 위주의 SAST가 잡지 못하는 '비즈니스 로직 및 아키텍처 결함(Business Logic Flaws)'을 찾는 것입니다.

[주요 탐지 타겟]
1. Broken Access Control (IDOR, 권한 우회)
2. Race Condition (동시성 처리 오류)
3. Input Logic Bypass (예상치 못한 값, 오버플로우 우회)
4. Hardcoded Secrets (DB, API Key 등)

[지시사항]
- 제공된 코드를 분석하여 타겟에 해당하는 결함만 도출하세요.
- 취약점이 전혀 없다면 억지로 만들어내지 마세요.
- 실제 Exploit 가능한 결함만 확인하세요. (단순 네이밍 컨벤션 미준수 등은 무시)
- (중요) 심각도가 LOW나 INFO인 사소한 건은 토큰 및 리포트 공간을 아끼기 위해 복잡한 분석(데이터 흐름 패스 등)을 생략하고, 직관적으로 5~6줄 이내로 간단하게 핵심만 언급하고 넘어가세요.
"""


# ──────────────────────────────────────────────
#  3) LangGraph 기반 Agent 클래스
# ──────────────────────────────────────────────

class OpenAIAgent:
    """
    Phase 3: LangGraph + 외부 검색(SerpAPI) 라우팅 기능을 결합한 완전 자율형 Agent.
    """

    MODEL_NAME = "gpt-5.4-mini"

    def __init__(self, isms_kb: Optional[ISMSKnowledgeBase] = None, osv_vulns: Optional[List[Dict[str, Any]]] = None) -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("[!] OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

        # Discovery Agent (가볍고 빠른 필터링) - Stage 2
        self.nano_llm = ChatOpenAI(model="gpt-5.4-nano", api_key=api_key, temperature=0.0)
        self.discovery_llm = self.nano_llm.with_structured_output(DiscoveryModel)
        
        # Analysis Agent (심층 분석 및 Tool Calling) - Stage 3
        self.mini_llm = ChatOpenAI(model="gpt-5.4-mini", api_key=api_key, temperature=0.1)
        self.structured_llm = self.mini_llm.with_structured_output(OutputModel)
        
        # MCP 도구 목록 바인딩
        self.tools = [read_source, search_code]
        self.nano_llm_with_tools = self.nano_llm.bind_tools(self.tools)
        
        self.isms_kb = isms_kb
        self.osv_vulns = osv_vulns or []
        self.graph = self._build_graph()

    def _build_graph(self):
        """LangGraph 워크플로우를 조립합니다."""
        workflow = StateGraph(AnalysisState)
        
        # 노드 선언
        workflow.add_node("discovery_node", self._discovery_node)
        workflow.add_node("analyze_node", self._analyze_node)
        workflow.add_node("mcp_tools", ToolNode(self.tools))
        workflow.add_node("search_node", self._search_node)
        workflow.add_node("final_report_node", self._final_report_node)
        
        # 제어 흐름(Edge) 선언
        workflow.add_edge(START, "discovery_node")
        workflow.add_conditional_edges("discovery_node", self._should_analyze)
        
        # Tool Node 루프 조건
        workflow.add_conditional_edges("analyze_node", self._should_continue_tools, {"tools": "mcp_tools", "final_report": "final_report_node"})
        workflow.add_edge("mcp_tools", "analyze_node")
        
        # 리포트 노드 -> 서치 (있으면) -> 리턴
        workflow.add_conditional_edges("final_report_node", self._should_search)
        workflow.add_edge("search_node", "final_report_node")
        
        return workflow.compile()
        
    def _should_analyze(self, state: AnalysisState) -> str:
        if state.get("is_vulnerable_candidate"):
            return "analyze_node"
        return END

    def _should_continue_tools(self, state: AnalysisState) -> str:
        messages = state.get("messages", [])
        if not messages:
            return "final_report"
        last_message = messages[-1]
        
        if getattr(last_message, "tool_calls", None):
            return "tools"
        return "final_report"

    def _should_search(self, state: AnalysisState) -> str:
        """라우터 로직: 검색 필요 시 검색 노드로 회귀, 아니면 종료."""
        if state.get("needs_search") and state.get("iteration", 0) < 1:
            return "search_node"
        return END

    def _search_node(self, state: AnalysisState) -> dict:
        """실제 웹 검색을 수행하고 결과를 상태(State)에 주입합니다."""
        query = state.get("search_query", "")
        print(f"  [🔍] Agent 능동형 웹 검색 실행 중 (query: '{query}')")
        try:
            res = perform_web_search(query)
        except Exception as e:
            print(f"  [!] 능동형 웹 검색 오류: {e}")
            res = "검색 실패"
        
        return {
            "search_result": res,
            "iteration": state.get("iteration", 0) + 1,
            "needs_search": False
        }

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
            
        sys_prompt = "너는 보안 분석 예비 검토자다. 전달받은 코드에서 취약점이나 논리적 오류 가능성이 1%라도 보이면 is_vulnerable_candidate를 true로 반환하라. 확실하게 100% 안전한 고정 문자열 반환 등의 코드만 false로 지정하라. 오탐을 적극적으로 허용한다."
        
        try:
            res: DiscoveryModel = self.discovery_llm.invoke([
                SystemMessage(content=sys_prompt),
                HumanMessage(content=prompt)
            ])
            if not res.is_vulnerable_candidate:
                print(f"  [Skip] 단계 2: 의심 없음으로 스킵됨 (이유: {res.reason})")
            return {"is_vulnerable_candidate": res.is_vulnerable_candidate}
        except Exception as e:
            # 예외 발생 시 안전을 고려하여 무조건 분석 단계를 통과
            return {"is_vulnerable_candidate": True}

    def _analyze_node(self, state: AnalysisState) -> dict:
        """Stage 3: Analysis Agent (nano 모델 + MCP Tools) CoT 딥다이브"""
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
            
            new_messages.append(SystemMessage(content=system_prompt))
            new_messages.append(HumanMessage(content=user_prompt))

        # LLM(Tool 바인딩됨) 실행 (React 에이전트 루프 수행)
        try:
            invoke_messages = messages + new_messages
            response = self.nano_llm_with_tools.invoke(invoke_messages)
            new_messages.append(response)
        except Exception as e:
            print(f"  [!] Analysis LLM 오류: {e}")
            
        return {"messages": new_messages}

    def _final_report_node(self, state: AnalysisState) -> dict:
        """분석(Tool Calling) 완료 후 최종 리포트를 Pydantic으로 산출"""
        messages = state.get("messages", [])
        
        # 이전 툴 호출과 분석 결과가 모두 담긴 컨텍스트를 기반으로 정리
        final_prompt = (
            "지금까지의 탐색 과정과 결과를 종합하여, 최종 취약점 보고서를 작성해주세요.\n"
            "**[중요] 응답은 오직 순수한 JSON 포맷으로만 반환해야 하며, 어떤 경우에도 "
            "마크다운 백틱(```json)이나 텍스트 설명 등 부가적인 문자열을 포함해서는 안 됩니다!**\n"
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
            # FIX 3: RAG 검색 정확도 향상. 
            # 단순히 코드 앞부분(500자)을 주는 대신, 직전에 Agent가 생각한 내용(CoT)을 기반으로 규정을 검색합니다.
            query_text = ""
            if messages and hasattr(messages[-1], "content") and messages[-1].content:
                query_text = messages[-1].content[:1500]  # CoT 추론 과정에서 핵심 키워드 검색
            
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
        
        try:
            result: OutputModel = self.structured_llm.invoke(invoke_messages)
            
            parsed_findings = []
            for f in result.findings:
                f_dict = f.model_dump(exclude_none=True)
                f_dict["source"] = "semgrep_verified" if state["context_type"] == "semgrep" else "deep_analysis"
                if state["context_type"] == "semgrep":
                    f_dict["original_file"] = state["context"].get("file_path", "")
                parsed_findings.append(f_dict)
                
            return {
                "findings": parsed_findings,
                "needs_search": result.needs_external_search,
                "search_query": result.search_query or ""
            }
            
        except Exception as e:
            print(f"[!] 최종 리포트 작성 실패: {e}")
            return {
                "findings": [],
                "needs_search": False,
                "search_query": ""
            }

    def analyze_semgrep_findings(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        
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
                "messages": []
            }
            # FIX 2: Rate Limit(429) 대비 Exponential Backoff 재시도 로직
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result_state = self.graph.invoke(initial_state)
                    return result_state.get("findings", [])
                except Exception as e:
                    if "429" in str(e) or "RateLimit" in str(e):
                        wait_time = 2 ** attempt
                        print(f"  [!] Rate Limit 발생. {wait_time}초 후 재시도... ({attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        print(f"  [!] Semgrep 검증 스레드 예외 발생: {e}")
                        break
            return []
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_process, ctx, i) for i, ctx in enumerate(contexts)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    print(f"  [!] Semgrep 검증 스레드 오류: {e}")
                    
        return all_findings

    def analyze_critical_logic(self, critical_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        
        import re
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
                "messages": []
            }
            
            # FIX 2: Rate Limit(429) 대비 Exponential Backoff 재시도 로직
            import time
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result_state = self.graph.invoke(initial_state)
                    return result_state.get("findings", [])
                except Exception as e:
                    if "429" in str(e) or "RateLimit" in str(e):
                        wait_time = 2 ** attempt
                        print(f"  [!] Rate Limit 발생. {wait_time}초 후 심층분석 재시도... ({attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        print(f"  [!] 심층 분석 스레드 예외 발생: {e}")
                        break
            return []
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_process, ctx, i) for i, ctx in enumerate(critical_files)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    print(f"  [!] 심층 분석 스레드 오류: {e}")
                    
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
