"""
방식 A: 단일 에이전트 (Mini Only, No-CoT)
- Nano 모델 필터링(Discovery) 단계 없음
- CoT(Chain-of-Thought) 프롬프트 없음 -> 즉각적인 결과 반환 요구
- 전체 코드를 한 번에 Mini 모델에 주입
"""
import os
import sys
import json
import time

from dotenv import load_dotenv
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(project_root, ".env"))

sys.path.insert(0, project_root)

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage


SYSTEM_PROMPT_NO_COT = """[Role: Application Security Engineer]
당신은 보안 분석가입니다. 제공된 코드를 분석하여 보안 취약점을 찾으세요.

[지시사항]
- 과정이나 사고 과정을 설명하지 마세요.
- 발견된 취약점을 즉시 아래 JSON 형식으로만 반환하세요.
- 취약점이 없으면 빈 배열을 반환하세요.

[출력 형식 (JSON만 반환)]
{
  "findings": [
    {
      "type": "취약점 유형",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "lines": [라인번호],
      "title": "취약점 제목 (한국어)",
      "description": "취약점 설명 (한국어)"
    }
  ]
}
"""


def run_method_a(target_dir):
    """단일 에이전트(Mini Only, No-CoT)로 디렉토리 내 모든 코드 스캔"""
    
    all_code_content = ""
    for filename in os.listdir(target_dir):
        if filename.endswith(".js"):
            file_path = os.path.join(target_dir, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                all_code_content += f"\n\n### 파일명: {filename}\n```javascript\n{f.read()}\n```\n"
    
    llm = ChatOpenAI(model="gpt-5.4-mini", temperature=0.0)
    
    user_prompt = f"""## 분석 대상 전체 코드
아래는 프로젝트의 모든 소스 코드입니다.

{all_code_content}

위 코드의 모든 보안 취약점을 즉시 JSON 형식으로 반환하세요. 반환 시 반드시 파일명(file_name) 필드도 포함하세요."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT_NO_COT.replace('"lines"', '"file_name": "파일명",\n      "lines"')),
        HumanMessage(content=user_prompt)
    ]
    
    start_time = time.time()
    response = llm.invoke(messages)
    elapsed = time.time() - start_time
    
    # 토큰 사용량 추출
    usage = response.usage_metadata if hasattr(response, "usage_metadata") else {}
    
    # 응답 파싱
    content = response.content.strip()
    # 마크다운 코드블록 제거
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()
    
    try:
        parsed = json.loads(content)
        findings = parsed.get("findings", [])
    except json.JSONDecodeError:
        print(f"  [!] JSON 파싱 실패. 원본 응답:\n{response.content[:500]}")
        findings = []
    
    result = {
        "method": "A (단일 에이전트, Mini Only, No-CoT)",
        "model": "gpt-5.4-mini",
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
    target = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tests", "fixtures", "vuln-test-app")
    print("[*] 방식 A (단일 에이전트, No-CoT) 실행 중...")
    result = run_method_a(target)
    
    print(f"\n[결과]")
    print(f"  모델: {result['model']}")
    print(f"  토큰: {result['tokens']}")
    print(f"  소요 시간: {result['time_seconds']}초")
    print(f"  탐지 수: {result['findings_count']}개")
    print(f"\n[탐지 내용]")
    print(json.dumps(result["findings"], indent=2, ensure_ascii=False))
    
    # 결과 저장
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    output_path = os.path.join(results_dir, "result_method_a.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 결과 저장: {output_path}")
