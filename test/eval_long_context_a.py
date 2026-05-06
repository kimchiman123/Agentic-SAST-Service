"""
Long Context 방식 A: 단일 에이전트 (Mini Only, No-CoT)
- mini_project5 전체 코드를 한 번에 Mini 모델에 주입
- CoT 없이 즉각적인 결과 반환 요구
- 기존 eval_method_a.py의 구조를 재사용
"""
import os
import sys
import json
import time

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage


# 분석 대상 확장자
TARGET_EXTENSIONS = {
    ".java", ".js", ".jsx", ".ts", ".tsx",
    ".yaml", ".yml", ".sh", ".py",
    ".properties", ".json", ".gradle",
}

# 제외 대상 (빌드 산출물, 의존성 등)
EXCLUDE_DIRS = {"node_modules", ".git", ".gradle", "build", "bin", ".idea", "__pycache__", "public"}
EXCLUDE_FILES = {"package-lock.json"}

SYSTEM_PROMPT_NO_COT = """[Role: Application Security Engineer]
당신은 보안 분석가입니다. 제공된 프로젝트 전체 코드를 분석하여 보안 취약점을 찾으세요.

[지시사항]
- 과정이나 사고 과정을 설명하지 마세요.
- 발견된 취약점을 즉시 아래 JSON 형식으로만 반환하세요.
- 취약점이 없으면 빈 배열을 반환하세요.
- 인프라 설정(K8s, Docker, CI/CD), 백엔드(Java/Spring), 프론트엔드(JS/React) 모두 분석하세요.

[출력 형식 (JSON만 반환)]
{
  "findings": [
    {
      "file_name": "파일 경로",
      "type": "취약점 유형",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "lines": [라인번호],
      "title": "취약점 제목 (한국어)",
      "description": "취약점 설명 (한국어)"
    }
  ]
}
"""


def collect_source_files(target_dir):
    """대상 디렉토리에서 분석 대상 파일 목록 수집"""
    files = []
    for root, dirs, filenames in os.walk(target_dir):
        # 제외 디렉토리 필터링
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        for filename in filenames:
            if filename in EXCLUDE_FILES:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext in TARGET_EXTENSIONS:
                files.append(os.path.join(root, filename))
    return files


def build_code_context(files, target_dir):
    """파일 목록을 하나의 코드 컨텍스트 문자열로 합침"""
    all_code = ""
    file_stats = []
    
    for file_path in files:
        rel_path = os.path.relpath(file_path, target_dir)
        ext = os.path.splitext(file_path)[1].lower()
        
        # 언어 태그 매핑
        lang_map = {
            ".java": "java", ".js": "javascript", ".jsx": "jsx",
            ".ts": "typescript", ".tsx": "tsx", ".yaml": "yaml",
            ".yml": "yaml", ".sh": "bash", ".py": "python",
            ".properties": "properties", ".json": "json",
            ".gradle": "groovy",
        }
        lang = lang_map.get(ext, "")
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            line_count = content.count("\n") + 1
            file_stats.append({"path": rel_path, "lines": line_count, "bytes": len(content)})
            all_code += f"\n\n### 파일: {rel_path}\n```{lang}\n{content}\n```\n"
        except Exception as e:
            print(f"  [!] 파일 읽기 실패: {rel_path} - {e}")
    
    return all_code, file_stats


def run_long_context_a(target_dir):
    """단일 에이전트(Mini Only, No-CoT)로 프로젝트 전체 코드 스캔"""
    
    print("[*] 소스 파일 수집 중...")
    files = collect_source_files(target_dir)
    print(f"  -> {len(files)}개 파일 수집됨")
    
    print("[*] 코드 컨텍스트 구성 중...")
    all_code, file_stats = build_code_context(files, target_dir)
    total_lines = sum(f["lines"] for f in file_stats)
    total_bytes = sum(f["bytes"] for f in file_stats)
    print(f"  -> 총 {total_lines}줄, {total_bytes:,} bytes")
    
    llm = ChatOpenAI(model="gpt-5.4-mini", temperature=0.0)
    
    user_prompt = f"""## 분석 대상 프로젝트 전체 코드
이 프로젝트는 Java Spring Boot 백엔드 + Next.js 프론트엔드 + K8s/Docker 인프라로 구성된 도서 관리 웹 애플리케이션입니다.
총 {len(files)}개 파일, {total_lines}줄의 코드입니다.

{all_code}

위 프로젝트의 모든 보안 취약점을 JSON 형식으로 반환하세요."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT_NO_COT),
        HumanMessage(content=user_prompt)
    ]
    
    print("[*] Mini 모델 분석 중... (전체 코드 일괄 주입)")
    start_time = time.time()
    response = llm.invoke(messages)
    elapsed = time.time() - start_time
    
    # 토큰 사용량 추출
    usage = response.usage_metadata if hasattr(response, "usage_metadata") else {}
    
    # 응답 파싱
    content = response.content.strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()
    
    try:
        parsed = json.loads(content)
        findings = parsed.get("findings", [])
    except json.JSONDecodeError:
        import re
        json_match = re.search(r"(\{.*\})", content, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                findings = parsed.get("findings", [])
            except:
                findings = []
        else:
            print(f"  [!] JSON 파싱 실패. 원본 응답:\n{response.content[:500]}")
            findings = []
    
    result = {
        "method": "A (단일 에이전트, Mini Only, No-CoT) - Long Context",
        "target": "mini_project5",
        "model": "gpt-5.4-mini",
        "project_stats": {
            "total_files": len(files),
            "total_lines": total_lines,
            "total_bytes": total_bytes,
            "file_details": file_stats
        },
        "tokens": {
            "prompt_tokens": usage.get("input_tokens", 0) if isinstance(usage, dict) else getattr(usage, "input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0) if isinstance(usage, dict) else getattr(usage, "output_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0) if isinstance(usage, dict) else getattr(usage, "total_tokens", 0)
        },
        "time_seconds": round(elapsed, 2),
        "findings_count": len(findings),
        "findings": findings
    }
    
    return result


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "mini_project5")
    print("=" * 60)
    print("[*] Long Context 방식 A (단일 에이전트, No-CoT) 실행 중...")
    print(f"[*] 대상: {target}")
    print("=" * 60)
    
    result = run_long_context_a(target)
    
    print(f"\n{'=' * 60}")
    print(f"[결과 요약]")
    print(f"  모델: {result['model']}")
    print(f"  프로젝트 규모: {result['project_stats']['total_files']}개 파일, {result['project_stats']['total_lines']}줄")
    print(f"  토큰: {result['tokens']}")
    print(f"  소요 시간: {result['time_seconds']}초")
    print(f"  탐지 수: {result['findings_count']}개")
    print(f"\n[탐지 내용]")
    for i, f in enumerate(result["findings"], 1):
        print(f"  {i}. [{f.get('severity','?')}] {f.get('title','N/A')} ({f.get('file_name','?')})")
    
    # 결과 저장
    output_path = os.path.join(os.path.dirname(__file__), "result_long_context_a.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 결과 저장: {output_path}")
