"""
OpenAI Agent 심층 분석 모듈.
GPT-5.4-mini를 활용하여 Semgrep 결과 검증 및 핵심 비즈니스 로직의 논리적 취약점을 분석합니다.
하네스 엔지니어링을 통해 Agent의 추론 범위와 출력 형식을 엄격히 제어합니다.
ISMS-P RAG 지식베이스와 연동하여 컴플라이언스 위반 여부도 함께 평가합니다.
"""
import os
import json
from typing import Any, Dict, List, Optional

from openai import OpenAI
from core.isms_rag import ISMSKnowledgeBase


# ──────────────────────────────────────────────
#  하네스 엔지니어링: System Prompt (Agent 제어)
# ──────────────────────────────────────────────

SYSTEM_PROMPT_SEMGREP_ANALYSIS = """당신은 클라우드 네이티브 환경에서 10년 이상 경력을 가진 수석 보안 감사관(Senior Security Auditor)입니다.

## 역할
Semgrep 정적 분석 도구가 탐지한 취약점 결과를 검증하고, 오탐(False Positive)을 필터링한 뒤 실제 위험이 존재하는 항목에 대해 공격 시나리오와 안전한 수정 코드를 제시합니다.

## 입력 데이터
- Semgrep이 탐지한 취약점 정보 (규칙 ID, 심각도, 메시지)
- 해당 취약점이 위치한 코드의 앞뒤 50줄 스니펫 (취약 라인은 >>> 마커로 표시됨)
- 프로젝트 디렉토리 구조

## 분석 지침
1. 제공된 코드 스니펫만을 근거로 판단하세요. 추측이나 가정을 하지 마세요.
2. 오탐(False Positive)인 경우, 왜 오탐인지 근거를 명확하게 제시하세요.
3. 실제 취약점(True Positive)인 경우, 구체적인 공격 시나리오(PoC)와 수정 코드를 작성하세요.
4. 심각도를 재평가하여 CRITICAL / HIGH / MEDIUM / LOW / INFO 중 하나로 분류하세요.
5. ISMS-P 관련 규약이 함께 제공된 경우, 해당 규약의 위반 여부도 반드시 평가하세요.

## 출력 형식
반드시 아래의 JSON 형식으로만 응답하세요. 다른 텍스트는 포함하지 마세요.
```json
{
  "findings": [
    {
      "rule_id": "semgrep 규칙 ID",
      "is_true_positive": true,
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "title": "취약점 제목 (한국어)",
      "description": "취약점 상세 설명 (한국어)",
      "exploit_scenario": "공격자가 이 취약점을 어떻게 악용할 수 있는지에 대한 상세 시나리오",
      "affected_code": "취약한 코드 라인",
      "remediation_code": "수정된 안전한 코드",
      "remediation_description": "수정 방법 설명 (한국어)",
      "isms_p_violation": "위반되는 ISMS-P 항목 번호 및 설명 (해당 없으면 null)"
    }
  ]
}
```"""

SYSTEM_PROMPT_DEEP_ANALYSIS = """당신은 클라우드 네이티브 환경 및 금융/보안 도메인에 정통한 수석 보안 감사관(Senior Security Auditor)입니다.

## 역할
일반적인 정적 분석 도구(SAST)나 패턴 매칭으로는 절대 찾아낼 수 없는 **'비즈니스 로직 결함(Business Logic Vulnerabilities)'**을 식별하는 심층 코드 감사(Code Audit)를 수행합니다.

## 중점 분석 항목
1. **인가 검증 누락 (Broken Access Control):** 사용자가 식별자(ID)를 조작하여 본인 소유가 아닌 리소스에 접근하거나 상태를 수정할 수 있는가? (IDOR 취약점 등)
2. **경쟁 상태 (Race Condition):** 동시에 여러 요청이 발생할 때 데이터 무결성(예: 잔액, 쿠폰 개수 등)이 훼손될 수 있는가?
3. **입력값 검증에 따른 로직 우회:** 비정상적 파라미터(예: 음수 금액)를 이용해 백엔드 처리 로직을 우회할 수 있는가?
4. **상태 관리 결함:** 토큰/세션 상태가 각 요청마다 적절하게 검증되고 있는가?
5. **민감 정보 노출:** 로그, 응답, 에러 메시지에 비밀번호, 키, 개인정보가 노출되는가?

## 분석 지침
1. 제공된 코드만을 근거로 판단하세요. 추측하지 마세요.
2. 단순 문법 오류, Code Smell, Lint 경고는 철저히 무시하세요.
3. 실제 해커 관점에서 서비스에 심각한 타격을 줄 수 있는 **익스플로잇 가능한 시나리오**만 보고하세요.
4. 취약점을 찾지 못했으면 빈 배열을 반환하세요. 억지로 취약점을 만들어내지 마세요.

## 출력 형식
반드시 아래의 JSON 형식으로만 응답하세요. 다른 텍스트는 포함하지 마세요.
```json
{
  "findings": [
    {
      "vulnerability_type": "IDOR | Race Condition | Logic Bypass | Session Flaw | Info Leak",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "title": "취약점 제목 (한국어)",
      "description": "취약점 상세 설명 (한국어)",
      "file_path": "취약점이 위치한 파일 경로",
      "affected_code": "취약한 코드 라인",
      "exploit_scenario": "공격자가 이 취약점을 어떻게 악용할 수 있는지에 대한 상세한 시나리오",
      "remediation_code": "수정된 안전한 코드",
      "remediation_description": "수정 방법 설명 (한국어)",
      "isms_p_violation": "위반되는 ISMS-P 항목 번호 및 설명 (해당 없으면 null)"
    }
  ]
}
```"""


class OpenAIAgent:
    """
    3단계: Agentic Reasoning을 담당하는 클래스.
    OpenAI GPT-5.4-mini API를 호출하여 취약점 오탐 여부, PoC 시나리오, 패치 코드를 추론합니다.
    """

    # 사용 모델 (GPT-5.4 Mini)
    MODEL_NAME = "gpt-5.4-mini"

    def __init__(self, isms_kb: Optional[ISMSKnowledgeBase] = None) -> None:
        """환경 변수에서 API 키를 읽고 OpenAI 클라이언트를 초기화합니다."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("[!] OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

        self.client = OpenAI(api_key=api_key)
        self.isms_kb = isms_kb

    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
        """
        OpenAI API를 호출하고 JSON 응답을 파싱합니다.

        Args:
            system_prompt: 시스템 프롬프트 (하네스 엔지니어링)
            user_prompt: 사용자 프롬프트 (분석 대상 데이터)

        Returns:
            파싱된 JSON 딕셔너리 또는 실패 시 None
        """
        try:
            response = self.client.chat.completions.create(
                model=self.MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,  # 보안 분석이므로 창의성을 최소화
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            return json.loads(content) if content else None

        except json.JSONDecodeError as e:
            print(f"[!] LLM 응답 JSON 파싱 실패: {e}")
            return None
        except Exception as e:
            print(f"[!] OpenAI API 호출 실패: {e}")
            return None

    def analyze_semgrep_findings(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Semgrep 탐지 결과를 Agent가 검증합니다 (오탐 필터링 + 심층 분석).

        Args:
            contexts: ContextExtractor.extract_contexts()의 반환값

        Returns:
            검증된 취약점 분석 결과 리스트
        """
        all_findings: List[Dict[str, Any]] = []

        for i, ctx in enumerate(contexts):
            print(f"  [→] Semgrep 결과 분석 중... ({i + 1}/{len(contexts)}) {ctx.get('file_path', '')}")

            user_prompt = self._build_semgrep_prompt(ctx)

            # ISMS-P RAG: 관련 규약을 검색하여 프롬프트에 삽입
            if self.isms_kb:
                isms_ref = self.isms_kb.search_for_code_context(
                    ctx.get("code_snippet", ""), ctx.get("file_path", "")
                )
                if isms_ref:
                    user_prompt += f"\n\n{isms_ref}"

            result = self._call_llm(SYSTEM_PROMPT_SEMGREP_ANALYSIS, user_prompt)

            if result and "findings" in result and isinstance(result["findings"], list):
                for finding in result["findings"]:
                    if isinstance(finding, dict):
                        finding["source"] = "semgrep_verified"
                        finding["original_file"] = ctx.get("file_path", "")
                        all_findings.append(finding)

        return all_findings

    def analyze_critical_logic(self, critical_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        핵심 비즈니스 로직 파일을 Agent가 직접 심층 분석합니다.
        (Tier 2: Semgrep이 놓칠 수 있는 논리적 취약점 탐지)

        Args:
            critical_files: ContextExtractor.extract_critical_files()의 반환값

        Returns:
            심층 분석으로 발견된 취약점 리스트
        """
        all_findings: List[Dict[str, Any]] = []

        for i, file_ctx in enumerate(critical_files):
            file_path = file_ctx.get("file_path", "")
            content = file_ctx.get("content", "")

            # 토큰 절약: 파일이 너무 크면 분할 처리
            if len(content) > 15000:
                print(f"  [→] 대용량 파일 스킵 (추후 분할 처리 구현 예정): {file_path}")
                continue

            print(f"  [→] 핵심 로직 심층 분석 중... ({i + 1}/{len(critical_files)}) {file_path}")

            # ISMS-P RAG: 관련 규약을 검색하여 프롬프트에 삽입
            isms_section = ""
            if self.isms_kb:
                isms_ref = self.isms_kb.search_for_code_context(content[:500], file_path)
                if isms_ref:
                    isms_section = f"\n\n{isms_ref}"

            user_prompt = f"""## 분석 대상 파일
파일 경로: {file_path}

## 소스코드
```
{content}
```
{isms_section}

위 코드에서 비즈니스 로직 결함을 분석하고, ISMS-P 규약 위반 여부도 함께 평가해주세요."""

            result = self._call_llm(SYSTEM_PROMPT_DEEP_ANALYSIS, user_prompt)

            if result and "findings" in result and isinstance(result["findings"], list):
                for finding in result["findings"]:
                    if isinstance(finding, dict):
                        finding["source"] = "deep_analysis"
                        all_findings.append(finding)

        return all_findings

    @staticmethod
    def _build_semgrep_prompt(ctx: Dict[str, Any]) -> str:
        """Semgrep 결과 기반 분석용 User Prompt를 구성합니다."""
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

위 Semgrep 탐지 결과가 오탐(False Positive)인지, 실제 취약점(True Positive)인지 검증하고
JSON 형식으로 분석 결과를 반환해주세요."""
