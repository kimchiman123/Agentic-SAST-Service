"""
Long Context 방식 B: 멀티 에이전트 (Nano 필터링 + Mini CoT)
- mini_project5 전체 파일을 Nano 모델로 사전 필터링 (Discovery)
- 필터링 통과 파일만 Mini 모델이 CoT 방식으로 심층 분석
- 기존 eval_method_b.py의 구조를 재사용
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

# 제외 대상
EXCLUDE_DIRS = {"node_modules", ".git", ".gradle", "build", "bin", ".idea", "__pycache__", "public"}
EXCLUDE_FILES = {"package-lock.json"}


def collect_source_files(target_dir):
    """대상 디렉토리에서 분석 대상 파일 목록 수집"""
    files = []
    for root, dirs, filenames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for filename in filenames:
            if filename in EXCLUDE_FILES:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext in TARGET_EXTENSIONS:
                files.append(os.path.join(root, filename))
    return files


def get_lang_tag(ext):
    """확장자별 언어 태그 반환"""
    lang_map = {
        ".java": "java", ".js": "javascript", ".jsx": "jsx",
        ".ts": "typescript", ".tsx": "tsx", ".yaml": "yaml",
        ".yml": "yaml", ".sh": "bash", ".py": "python",
        ".properties": "properties", ".json": "json",
        ".gradle": "groovy",
    }
    return lang_map.get(ext, "")


def run_long_context_b(target_dir):
    """멀티 에이전트(Nano + Mini, CoT)로 프로젝트 스캔"""
    
    api_key = os.environ.get("OPENAI_API_KEY")
    nano_llm = ChatOpenAI(model="gpt-5.4-nano", api_key=api_key, temperature=0.0)
    mini_llm = ChatOpenAI(model="gpt-5.4-mini", api_key=api_key, temperature=0.1)
    
    print("[*] 소스 파일 수집 중...")
    files = collect_source_files(target_dir)
    print(f"  -> {len(files)}개 파일 수집됨")
    
    # 프로젝트 통계
    file_stats = []
    total_findings = []
    total_nano_tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    total_mini_tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    total_time = 0
    filtered_out_files = []
    analyzed_files = []
    
    for file_path in files:
        rel_path = os.path.relpath(file_path, target_dir)
        ext = os.path.splitext(file_path)[1].lower()
        lang = get_lang_tag(ext)
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code_content = f.read()
            line_count = code_content.count("\n") + 1
            file_stats.append({"path": rel_path, "lines": line_count, "bytes": len(code_content)})
        except Exception as e:
            print(f"  [!] 파일 읽기 실패: {rel_path} - {e}")
            continue
        
        # ===== Stage 1: Nano 모델 Discovery =====
        discovery_prompt = f"""너는 보안 분석 예비 검토자(Discovery Agent)다.
전달받은 코드를 분석하여 보안상 '위험 가능성'이 있는지 1차적으로 판단하라.

[안전 판정 기준 (false 반환)]
다음 중 하나라도 해당되며, 인증/DB/파일처리/인프라보안과 무관하다면 무조건 `is_vulnerable_candidate: false`를 반환하라.
1. 순수 UI, 프론트엔드 렌더링 또는 DOM 조작 코드 (단, 인증/세션/민감정보 처리 제외)
2. 문자열 가공, 수학 계산, 정렬 등 단순 유틸리티 로직
3. 더미 데이터, 상수 파일, 빌드 설정, 테스트 코드
4. DTO, Entity 등 데이터 구조 정의만 포함된 코드

[위험 판정 기준 (true 반환)]
다음 단어/패턴이 포함되어 있거나 관련 로직이 1줄이라도 있다면 반드시 `is_vulnerable_candidate: true`를 반환하라.
1. 인증/인가 (JWT, session, password, login, auth, role, token, credential)
2. 외부 데이터 처리 (eval, request, body, sql, query, fs, exec, Runtime)
3. 파일 업로드/다운로드 (upload, download, transferTo, MultipartFile)
4. 인프라 보안 (Secret, password, CORS, allowedOrigins, env, credential)
5. 네트워크/크롤링 (URL, connect, openStream, Jsoup, fetch)
6. 금융/비즈니스 중요 상태 (balance, amount, pay, transfer)

## 분석 대상 코드 ({rel_path})
```{lang}
{code_content}
```

반드시 JSON 형식으로만 응답:
{{"is_vulnerable_candidate": true/false, "reason": "판단 이유"}}"""

        print(f"  [Stage 1] {rel_path} Nano 필터링 중...")
        nano_start = time.time()
        nano_response = nano_llm.invoke([HumanMessage(content=discovery_prompt)])
        nano_elapsed = time.time() - nano_start
        total_time += nano_elapsed
        
        # 토큰 집계
        nano_usage = nano_response.usage_metadata if hasattr(nano_response, "usage_metadata") else {}
        total_nano_tokens["prompt_tokens"] += nano_usage.get("input_tokens", 0) if isinstance(nano_usage, dict) else getattr(nano_usage, "input_tokens", 0)
        total_nano_tokens["completion_tokens"] += nano_usage.get("output_tokens", 0) if isinstance(nano_usage, dict) else getattr(nano_usage, "output_tokens", 0)
        total_nano_tokens["total_tokens"] += nano_usage.get("total_tokens", 0) if isinstance(nano_usage, dict) else getattr(nano_usage, "total_tokens", 0)
        
        # 파싱
        nano_content = nano_response.content.strip()
        if nano_content.startswith("```"):
            nano_content = nano_content.split("```")[1]
            if nano_content.startswith("json"):
                nano_content = nano_content[4:]
        
        try:
            is_candidate = json.loads(nano_content.strip()).get("is_vulnerable_candidate", True)
        except:
            is_candidate = True
            
        if not is_candidate:
            print(f"    -> [안전 판정] 필터링됨 (Mini 분석 생략)")
            filtered_out_files.append(rel_path)
            continue
            
        print(f"    -> [의심 판정] Mini 분석기로 전달됨")
        analyzed_files.append(rel_path)
        
        # ===== Stage 2: Mini 모델 심층 분석 =====
        cot_system_prompt = """[Role: Senior Application Security Engineer]
당신의 목표는 비즈니스 로직 및 보안 취약점을 심층 분석하는 것입니다.

[지시사항]
1. 먼저 코드 전체를 읽고, 데이터 흐름(Source → Sink)을 추적하세요.
2. 각 의심 지점에 대해 단계별로 논리적 추론 과정(Chain-of-Thought)을 상세히 서술하세요.
3. 추론이 완료되면 각 취약점의 decision_tree를 반드시 작성하세요.
4. 최종적으로 아래 JSON 형식으로 결과를 출력하세요.
5. 인프라 설정(K8s, Docker, YAML)도 보안 관점에서 분석하세요.

[출력 형식 (JSON만 반환)]
{
  "findings": [
    {
      "file_name": "파일명",
      "type": "취약점 유형",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "lines": [라인번호],
      "title": "취약점 제목 (한국어)",
      "description": "취약점 설명 (한국어)",
      "exploit_scenario": "공격 시나리오",
      "decision_tree": ["추론 단계 1", "추론 단계 2", "..."]
    }
  ]
}"""

        user_prompt = f"""## 분석 대상 파일
파일 경로: {rel_path}

## 전체 소스 코드
```{lang}
{code_content}
```

위 코드를 단계별로 분석하여 보안 취약점을 찾고, 논리적 추론 과정과 함께 JSON 형식으로 반환하세요."""

        print(f"  [Stage 2] {rel_path} Mini 심층 분석 중...")
        mini_start = time.time()
        mini_response = mini_llm.invoke([
            SystemMessage(content=cot_system_prompt),
            HumanMessage(content=user_prompt)
        ])
        mini_elapsed = time.time() - mini_start
        total_time += mini_elapsed
        
        # 토큰 집계
        mini_usage = mini_response.usage_metadata if hasattr(mini_response, "usage_metadata") else {}
        total_mini_tokens["prompt_tokens"] += mini_usage.get("input_tokens", 0) if isinstance(mini_usage, dict) else getattr(mini_usage, "input_tokens", 0)
        total_mini_tokens["completion_tokens"] += mini_usage.get("output_tokens", 0) if isinstance(mini_usage, dict) else getattr(mini_usage, "output_tokens", 0)
        total_mini_tokens["total_tokens"] += mini_usage.get("total_tokens", 0) if isinstance(mini_usage, dict) else getattr(mini_usage, "total_tokens", 0)
        
        # 파싱
        content = mini_response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        try:
            parsed = json.loads(content.strip())
            findings = parsed.get("findings", [])
            for f_item in findings:
                f_item["file_name"] = rel_path
            total_findings.extend(findings)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r"(\{.*\})", content, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(1))
                    findings = parsed.get("findings", [])
                    for f_item in findings:
                        f_item["file_name"] = rel_path
                    total_findings.extend(findings)
                except:
                    pass
    
    total_lines = sum(f["lines"] for f in file_stats)
    total_bytes = sum(f["bytes"] for f in file_stats)
    
    return {
        "method": "B (멀티 에이전트, Nano+Mini, CoT) - Long Context",
        "target": "mini_project5",
        "models": {"discovery": "gpt-5.4-nano", "analysis": "gpt-5.4-mini"},
        "project_stats": {
            "total_files": len(files),
            "total_lines": total_lines,
            "total_bytes": total_bytes,
            "file_details": file_stats
        },
        "tokens": {
            "nano": total_nano_tokens,
            "mini": total_mini_tokens,
            "total_tokens": total_nano_tokens["total_tokens"] + total_mini_tokens["total_tokens"]
        },
        "time_seconds": round(total_time, 2),
        "findings_count": len(total_findings),
        "findings": total_findings,
        "filtered_files": filtered_out_files,
        "analyzed_files": analyzed_files,
        "filter_stats": {
            "total_files": len(files),
            "filtered_count": len(filtered_out_files),
            "analyzed_count": len(analyzed_files),
            "filter_rate_pct": round(len(filtered_out_files) / max(len(files), 1) * 100, 1)
        }
    }


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "mini_project5")
    print("=" * 60)
    print("[*] Long Context 방식 B (멀티 에이전트, CoT) 실행 중...")
    print(f"[*] 대상: {target}")
    print("=" * 60)
    
    result = run_long_context_b(target)
    
    print(f"\n{'=' * 60}")
    print(f"[결과 요약]")
    print(f"  모델: {result['models']}")
    print(f"  프로젝트 규모: {result['project_stats']['total_files']}개 파일, {result['project_stats']['total_lines']}줄")
    print(f"  토큰 - Nano: {result['tokens']['nano']}")
    print(f"  토큰 - Mini: {result['tokens']['mini']}")
    print(f"  토큰 - 합산: {result['tokens']['total_tokens']}")
    print(f"  필터링률: {result['filter_stats']['filter_rate_pct']}% ({result['filter_stats']['filtered_count']}/{result['filter_stats']['total_files']})")
    print(f"  필터링된 파일: {result['filtered_files']}")
    print(f"  분석된 파일: {result['analyzed_files']}")
    print(f"  소요 시간: {result['time_seconds']}초")
    print(f"  탐지 수: {result['findings_count']}개")
    print(f"\n[탐지 내용]")
    for i, f in enumerate(result["findings"], 1):
        print(f"  {i}. [{f.get('severity','?')}] {f.get('title','N/A')} ({f.get('file_name','?')})")
    
    # 결과 저장
    output_path = os.path.join(os.path.dirname(__file__), "result_long_context_b.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 결과 저장: {output_path}")
