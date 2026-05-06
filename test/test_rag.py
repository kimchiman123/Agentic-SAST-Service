"""ISMS-P RAG 지식베이스 빌드 및 검색 테스트"""
from core.isms_rag import ISMSKnowledgeBase

# 지식베이스 빌드
kb = ISMSKnowledgeBase()
kb.build_knowledge_base()

# 검색 테스트 1: 비밀번호 암호화
print("\n[테스트 1] 비밀번호 암호화 관련 규약 검색:")
results = kb.search("비밀번호 암호화 저장", n_results=3)
for i, r in enumerate(results, 1):
    text_preview = r["text"][:150].replace("\n", " ")
    dist = r["distance"]
    print(f"  [{i}] (거리: {dist:.4f}) {text_preview}...")
    print(f"      메타: {r['metadata']}")

# 검색 테스트 2: 접근 통제
print("\n[테스트 2] 접근 통제 관련 규약 검색:")
results2 = kb.search("접근 통제 인증 세션 토큰", n_results=3)
for i, r in enumerate(results2, 1):
    text_preview = r["text"][:150].replace("\n", " ")
    dist = r["distance"]
    print(f"  [{i}] (거리: {dist:.4f}) {text_preview}...")
    print(f"      메타: {r['metadata']}")

print("\n[+] RAG 지식베이스 테스트 완료!")
