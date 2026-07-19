import os
import sys
import json
from dotenv import load_dotenv
load_dotenv()


# Agentic-SAST-Service 경로 추가
base_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(base_dir))
sys.path.append(project_root)

from core.isms_rag import ISMSKnowledgeBase
from datasets import Dataset
from ragas import evaluate
from ragas.run_config import RunConfig
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

    # 2. 증강된 평가용 데이터셋 로드
    dataset_path = os.path.join(base_dir, "ragas_eval_dataset_augmented.json")
    if not os.path.exists(dataset_path):
        print(f"[!] 데이터셋 파일을 찾을 수 없습니다: {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    questions = [item["question"] for item in eval_data]
    ground_truths = [item["ground_truth"] for item in eval_data]

    answers = []
    contexts_list = []

    # LLM 준비 (답변 생성 및 평가용)
    llm = ChatOpenAI(model="gpt-5.4", temperature=0)

    # RAG 컨텍스트를 충실하게 반영하도록 조정한 프롬프트
    prompt = ChatPromptTemplate.from_messages([
        ("system", "당신은 ISMS-P 보안 컨설턴트 및 시큐어 코딩 전문가입니다. 아래 제공된 RAG 컨텍스트(ISMS-P 기준 및 기술 가이드)를 철저히 바탕으로 사용자의 질문에 답변하세요.\n답변 작성 시 반드시 검색된 RAG 컨텍스트 문서에 명시된 구체적인 문장과 조항 명칭(예: '2.8.1 보안 요구사항 정의', '2.7.1 암호정책 적용' 등)을 본문에 직접적으로 언급하고, 이를 기준으로 취약점의 위반 사항과 조치 방안을 명확히 대조하여 답하세요.\n\n컨텍스트:\n{context}"),
        ("human", "{question}")
    ])
    chain = prompt | llm

    print("[*] RAG 응답 생성 중...", flush=True)
    for idx, q in enumerate(questions, 1):
        print(f"  - [{idx}/{len(questions)}] RAG 검색 중: {q[:25].replace('\n', ' ')}...", flush=True)
        # 검색 (Top 3)
        search_results = rag.search(q, n_results=3) if hasattr(rag, 'search') else rag._search_vector(q, n_results=3)

        # 하이브리드 검색 fallback 처리
        if not search_results:
            vec_res = rag._search_vector(q, n_results=3)
            bm25_res = rag._search_bm25(q, n_results=3)
            seen = set()
            search_results = []
            for r in vec_res + bm25_res:
                if r["id"] not in seen:
                    seen.add(r["id"])
                    search_results.append(r)

        ctx_texts = [res["text"] for res in search_results[:3]]
        contexts_list.append(ctx_texts)

        # LLM 응답 생성
        print(f"  - [{idx}/{len(questions)}] GPT-5.4 답변 생성 요청 중...", flush=True)
        combined_context = "\n\n".join(ctx_texts)
        answer = chain.invoke({"context": combined_context, "question": q})
        answers.append(answer.content)
        print(f"  - [{idx}/{len(questions)}] 답변 완료", flush=True)

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
        llm=llm,
        run_config=RunConfig(max_workers=1)
    )

    df = result.to_pandas()
    print("\n========== [증강 데이터셋 평가 결과 요약] ==========")
    print(result)
    print("\n========== [상세 결과] ==========")
    print(df)

    # 파일로 저장
    output_path = os.path.join(base_dir, "results", "rag_evaluation_augmented_results.csv")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"\n[+] 평가 결과가 {output_path}에 저장되었습니다.")

if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY가 설정되어 있지 않습니다.")
        sys.exit(1)
    run_evaluation()
