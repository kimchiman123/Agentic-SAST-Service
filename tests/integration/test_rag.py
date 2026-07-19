"""ISMS-P RAG 지식베이스 빌드 및 검색 통합 테스트."""

import os

import pytest

from core.isms_rag import ISMSKnowledgeBase


@pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="RUN_INTEGRATION_TESTS=1일 때만 RAG 자산 빌드를 실행합니다.",
)
def test_rag_build_and_search() -> None:
    knowledge_base = ISMSKnowledgeBase()
    knowledge_base.build_knowledge_base()

    password_results = knowledge_base.search("비밀번호 암호화 저장", n_results=3)
    access_results = knowledge_base.search("접근 통제 인증 세션 토큰", n_results=3)

    assert password_results
    assert access_results
    assert all("text" in result and "metadata" in result for result in password_results)
