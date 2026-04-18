"""
LangGraph에서 사용할 상태(State) 정의 모델입니다.
하나의 코드 컨텍스트(Semgrep 조각 또는 단일 파일)가 퍼이프라인을 통과할 때의 단위 상태를 나타냅니다.
"""
from typing import TypedDict, List, Dict, Any

class AnalysisState(TypedDict):
    """
    단일 코드 컨텍스트 분석을 위한 상태 모델
    
    Attributes:
        context: 에이전트가 분석할 현재 코드 정보
        context_type: 분석의 종류 ('semgrep' 또는 'deep_analysis')
        findings: 현재 컨텍스트에서 추출된 취약점 리스트
        needs_search: (향후 확장) SerpAPI 등 외부 검색 필요 여부
        search_query: (향후 확장) 외부 검색 시 사용할 쿼리 문자열
    """
    context: Dict[str, Any]
    context_type: str
    findings: List[Dict[str, Any]]
    needs_search: bool
    search_query: str
    search_result: str
    iteration: int
