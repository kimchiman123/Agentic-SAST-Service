"""
무료 웹 검색 엔진 모듈 (DuckDuckGo Search)
에이전트가 알려지지 않은 새로운 취약점이나 OSV 정보가 부족한 CVE의
최신 PoC (Proof of Concept) 등을 수집할 때 사용합니다.
"""
from ddgs import DDGS
from typing import List

def perform_web_search(query: str, max_results: int = 3) -> str:
    """
    DuckDuckGo 검색을 수행하고 텍스트 형태의 결과를 반환합니다.
    """
    try:
        with DDGS() as ddgs:
            results: List[dict] = list(ddgs.text(query, max_results=max_results))
            
            if not results:
                return "검색 결과가 없습니다."
                
            formatted_results = []
            for i, r in enumerate(results, 1):
                title = r.get("title", "")
                body = r.get("body", "")
                link = r.get("href", "")
                formatted_results.append(f"[{i}] {title}\n요약: {body}\n출처: {link}")
                
            return "\n\n".join(formatted_results)
    except Exception as exc:
        print(f"  [!] 웹 검색 중 오류 발생: {type(exc).__name__}")
        return "웹 검색 통신 실패"
