import os
import sys
from dotenv import load_dotenv
load_dotenv()

# Agentic-SAST-Service 경로 추가
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(base_dir)

from core.isms_rag import ISMSKnowledgeBase
from datasets import Dataset
from ragas import evaluate
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    context_recall,
    context_precision,
)
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

def run_evaluation():
    # 1. 지식베이스 준비
    rag = ISMSKnowledgeBase()
    rag.ensure_ready()
    
    # 2. 평가용 데이터셋 (ISMS-P 관련 질문들)
    questions = [
        "웹 애플리케이션에서 비밀번호를 저장할 때 지켜야 할 규정은 무엇인가요?",
        "세션 타임아웃을 설정해야 하는 이유와 ISMS-P 기준은 무엇인가요?",
        "사용자 인증 정보 전송 시 보호 대책은 무엇이 있나요?"
    ]
    
    ground_truths = [
        "비밀번호는 안전한 알고리즘을 사용하여 일방향 암호화(해시)하여 저장해야 합니다.",
        "일정 시간 동안 애플리케이션을 사용하지 않는 경우, 세션을 종료하여 불법적인 사용 및 세션 탈취를 방지해야 합니다.",
        "인증 정보(비밀번호 등)는 전송 시 암호화 통신(HTTPS 등)을 통해 보호되어야 합니다."
    ]
    
    answers = []
    contexts_list = []
    
    # LLM 준비 (답변 생성용)
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0) # 평가를 위해 저비용/고효율 모델 사용
    prompt = ChatPromptTemplate.from_messages([
        ("system", "다음 제공된 ISMS-P 컨텍스트를 바탕으로 사용자의 질문에 정확하고 간결하게 답변하세요.\n\n컨텍스트:\n{context}"),
        ("human", "{question}")
    ])
    chain = prompt | llm
    
    print("[*] RAG 응답 생성 중...")
    for q in questions:
        # 검색 (Top 8 - 넓은 후보 풀)
        search_results = rag.search(q, n_results=8)
        ctx_texts = [res["text"] for res in search_results]
        contexts_list.append(ctx_texts)
        
        # LLM 응답 생성
        combined_context = "\n\n".join(ctx_texts)
        answer = chain.invoke({"context": combined_context, "question": q})
        answers.append(answer.content)
        
    # 3. Ragas 데이터셋 구성
    data = {
        "question": questions,
        "answer": answers,
        "contexts": contexts_list,
        "ground_truth": ground_truths
    }
    dataset = Dataset.from_dict(data)
    
    print("\n[*] Ragas 평가 시작...")
    # 평가 수행
    result = evaluate(
        dataset,
        metrics=[
            context_precision,
            context_recall,
            faithfulness,
            answer_relevancy,
        ],
        llm=llm
    )
    
    df = result.to_pandas()
    print("\n========== [평가 결과 요약] ==========")
    print(result)
    print("\n========== [상세 결과] ==========")
    print(df)
    
    # 파일로 저장
    df.to_csv(os.path.join(base_dir, "rag_evaluation_results.csv"), index=False)
    print(f"\n[+] 평가 결과가 {os.path.join(base_dir, 'rag_evaluation_results.csv')}에 저장되었습니다.")

if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY가 설정되어 있지 않습니다.")
        # sys.exit(1)
    run_evaluation()
