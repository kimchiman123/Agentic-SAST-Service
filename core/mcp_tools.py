import os
import subprocess
from langchain_core.tools import tool

@tool
def read_source(file_path: str, start_line: int, end_line: int) -> str:
    """지정된 파일의 특정 라인 범위(start_line ~ end_line)의 소스코드를 읽어옵니다.
    
    Args:
        file_path: 프로젝트 디렉토리 기준의 상대 경로 또는 절대 경로
        start_line: 읽어올 시작 라인 (1-indexed)
        end_line: 읽어올 끝 라인 (1-indexed)
    """
    try:
        if not os.path.isfile(file_path):
            return f"[Error] 파일을 찾을 수 없습니다: {file_path}"
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
        start = max(1, start_line)
        end = min(len(lines), end_line)
        
        if start > end:
            return "[Error] start_line이 end_line보다 큽니다."
            
        snippet = lines[start - 1 : end]
        numbered_snippet = [f"{start + i}: {line}" for i, line in enumerate(snippet)]
        return "".join(numbered_snippet)
    except Exception as e:
        return f"[Error] 소스 코드 읽기 실패: {str(e)}"

@tool
def search_code(query: str, dir_path: str = ".") -> str:
    """ripgrep(rg)을 사용하여 디렉토리 내에서 특정 문자열(함수명, 변수명 등)이 사용된 위치를 고속으로 검색합니다.
    주의: 이 도구는 시스템에 'rg' (ripgrep) 바이너리가 설치되어 있어야 정상 동작합니다.
    
    Args:
        query: 검색할 문자열 패턴
        dir_path: 검색을 수행할 디렉토리 경로 (기본값은 현재 디렉토리)
    """
    try:
        # rg가 있는지 확인
        try:
            subprocess.run(["rg", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            has_rg = True
        except FileNotFoundError:
            has_rg = False
            
        if has_rg:
            result = subprocess.run(
                ["rg", "-n", query, dir_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            output = result.stdout.strip()
            if not output:
                return f"[Result] '{query}' 검색 결과가 없습니다."
            
            # 검색 결과가 너무 길면 자르기 (컨텍스트 한도 고려)
            lines = output.split('\n')
            if len(lines) > 100:
                output = '\n'.join(lines[:100]) + f"\n... (총 {len(lines)}개의 결과. 상위 100개만 표시합니다)"
            return output
            
        else:
            # Fallback 로직 (ripgrep이 없을 경우를 대비한 파이썬 내장 검색 로직)
            return "[Warning] 시스템에 ripgrep(rg)이 설치되어 있지 않습니다. 더 정확한 검색을 위해 ripgrep을 설치해주세요.\n"
    except Exception as e:
        return f"[Error] 검색 실행 실패: {str(e)}"
