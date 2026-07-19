import os
import sys
from dotenv import load_dotenv
load_dotenv()

# Agentic-SAST-Service 경로 추가
base_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(base_dir))
sys.path.append(project_root)

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
    
    # 2. 평가용 데이터셋 (ISMS-P 관련 질문들 동적 로드)
    import json
    dataset_path = os.path.join(base_dir, "ragas_eval_dataset.json")
    if not os.path.exists(dataset_path):
        print(f"[!] 데이터셋 파일을 찾을 수 없습니다: {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    questions = [item["question"] for item in eval_data]
    ground_truths = [item["ground_truth"] for item in eval_data]
    
    answers = []
    contexts_list = []
    
    # LLM 준비 (답변 생성용 및 평가용)
    llm = ChatOpenAI(model="gpt-5.4-mini", temperature=0)
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
    output_path = os.path.join(base_dir, "results", "rag_evaluation_results.csv")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"\n[+] 평가 결과가 {output_path}에 저장되었습니다.")

if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY가 설정되어 있지 않습니다.")
        # sys.exit(1)
    run_evaluation()
