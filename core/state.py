"""
LangGraph에서 사용할 상태(State) 정의 모델입니다.
하나의 코드 컨텍스트(Semgrep 조각 또는 단일 파일)가 퍼이프라인을 통과할 때의 단위 상태를 나타냅니다.
"""
from dataclasses import dataclass, field
from typing import TypedDict, List, Dict, Any, Annotated, Literal
import operator


StageName = Literal["semgrep", "agent", "verification", "report"]
StageStatus = Literal["pending", "running", "completed", "partial", "failed", "skipped"]


@dataclass(frozen=True)
class StageEvent:
    """Safe, incremental pipeline event for a local UI.

    Payloads intentionally contain only summaries and stable IDs: API keys and
    source text must never cross this boundary.
    """

    run_id: str
    stage: StageName
    status: StageStatus
    current: int = 0
    total: int = 0
    message: str = ""
    error_code: str | None = None
    payload: Dict[str, Any] = field(default_factory=dict)

class AnalysisState(TypedDict, total=False):
    """
    단일 코드 컨텍스트 분석을 위한 상태 모델
    
    Attributes:
        context: 에이전트가 분석할 현재 코드 정보
        context_type: 분석의 종류 ('semgrep' 또는 'deep_analysis')
        is_vulnerable_candidate: Discovery 에이전트가 판단한 취약점 가능성
        findings: 현재 컨텍스트에서 추출된 취약점 리스트
        needs_search: (향후 확장) SerpAPI 등 외부 검색 필요 여부
        search_query: (향후 확장) 외부 검색 시 사용할 쿼리 문자열
        messages: ToolNode 등을 위한 LLM 메시지 히스토리 (LangGraph 호환용)
    """
    context: Dict[str, Any]
    context_type: str
    is_vulnerable_candidate: bool
    findings: List[Dict[str, Any]]
    needs_search: bool
    search_query: str
    search_result: str
    iteration: int
    messages: Annotated[List[Any], operator.add]
    analysis_plan: Dict[str, Any]
    candidate_findings: List[Dict[str, Any]]
    verification: Dict[str, Any]
    tool_rounds: int
    max_tool_rounds: int
    revision_count: int
    web_search_count: int
    phase: str
    stop_reason: str
    errors: List[str]
