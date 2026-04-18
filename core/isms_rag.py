"""
ISMS-P RAG(검색 증강 생성) 지식베이스 모듈.
ISMS-P 인증기준 XLSX/PDF 에셋을 파싱하여 ChromaDB 벡터 DB에 저장하고,
코드 분석 시 관련 규약을 검색하여 Agent에게 제공합니다.
"""
import os
import re
from typing import Any, Dict, List, Optional

import openpyxl
import fitz  # PyMuPDF
import chromadb

# 에셋 경로 (프로젝트 최상위 기준)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET_DIR = os.path.join(BASE_DIR, "asset")
XLSX_PATH = os.path.join(ASSET_DIR, "ISMS-P_인증기준_세부점검항목.xlsx")
PDF_PATH = os.path.join(ASSET_DIR, "ISMS-P 인증기준 안내서(2023.11.23).pdf")

# ChromaDB 로컬 저장 경로
CHROMA_PERSIST_DIR = os.path.join(BASE_DIR, ".chroma_db")
COLLECTION_NAME = "isms_p_knowledge"


# ──────────────────────────────────────────────
#  1) XLSX 파싱: 세부점검항목 구조화
# ──────────────────────────────────────────────

def parse_xlsx_checklist(xlsx_path: str = XLSX_PATH) -> List[Dict[str, str]]:
    """
    ISMS-P 세부점검항목 엑셀을 파싱하여 구조화된 체크리스트를 반환합니다.
    병합 셀로 인해 빈 값이 많으므로, 직전 값을 이어받는(forward-fill) 방식으로 처리합니다.

    Returns:
        항목별 딕셔너리 리스트 (분야, 항목번호, 항목명, 상세내용, 확인사항)
    """
    if not os.path.exists(xlsx_path):
        print(f"[!] XLSX 파일을 찾을 수 없습니다: {xlsx_path}")
        return []

    wb = openpyxl.load_workbook(xlsx_path)
    all_items: List[Dict[str, str]] = []

    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        # 현재 분야/항목 번호/상세내용을 추적 (forward-fill용)
        current_field = ""
        current_item_no = ""
        current_item_name = ""
        current_detail = ""

        for row in ws.iter_rows(min_row=2, values_only=True):
            cells = [str(c).strip() if c else "" for c in row]

            # 최소 6개 열이 있어야 유효
            if len(cells) < 6:
                continue

            # 분야 갱신 (예: "1.1.", "2.5.")
            if cells[1] and re.match(r'^\d+\.\d+\.?', cells[1]):
                current_field = cells[1].strip()
                if cells[2]:
                    current_field += f" {cells[2].strip()}"

            # 항목번호 갱신 (예: "1.1.1", "2.5.4")
            if cells[3] and re.match(r'^\d+\.\d+\.\d+', cells[3]):
                current_item_no = cells[3].strip()
                current_item_name = cells[4].strip() if cells[4] else ""

            # 상세내용 갱신
            if cells[5]:
                current_detail = cells[5].strip()

            # 주요 확인사항이 있으면 레코드 생성
            check_col = cells[6] if len(cells) > 6 else ""
            if check_col and current_item_no:
                item = {
                    "sheet": sheet_name,
                    "field": current_field,
                    "item_no": current_item_no,
                    "item_name": current_item_name,
                    "detail": current_detail,
                    "check_point": check_col,
                }
                all_items.append(item)

    print(f"[+] XLSX 파싱 완료: {len(all_items)}개 점검항목 추출")
    return all_items


# ──────────────────────────────────────────────
#  2) PDF 파싱: 안내서 텍스트 청킹
# ──────────────────────────────────────────────

def parse_pdf_guide(pdf_path: str = PDF_PATH, chunk_size: int = 1500) -> List[Dict[str, str]]:
    """
    ISMS-P 인증기준 안내서 PDF를 페이지별로 읽어 텍스트 청크로 분할합니다.

    Args:
        pdf_path: PDF 파일 경로
        chunk_size: 각 청크의 최대 문자 수

    Returns:
        청크별 딕셔너리 리스트 (page, chunk_index, text)
    """
    if not os.path.exists(pdf_path):
        print(f"[!] PDF 파일을 찾을 수 없습니다: {pdf_path}")
        return []

    doc = fitz.open(pdf_path)
    chunks: List[Dict[str, str]] = []

    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text("text").strip()

        if not text or len(text) < 20:
            continue

        # 청크 단위로 분할 (문장 경계 존중)
        start = 0
        chunk_idx = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))

            # 문장 경계에서 자르기 (마침표, 줄바꿈 기준)
            if end < len(text):
                last_period = text.rfind(".", start, end)
                last_newline = text.rfind("\n", start, end)
                cut_point = max(last_period, last_newline)
                if cut_point > start:
                    end = cut_point + 1

            chunk_text = text[start:end].strip()
            if chunk_text:
                # PDF 청크 내에서 ISMS-P 조항 번호 추출 시도 (예: 2.6.1)
                clause_match = re.search(r'(?:^|\s)((?:1|2|3)\.\d+\.\d+)(?:\s|[^\d]|$)', chunk_text)
                item_no = clause_match.group(1).strip() if clause_match else ""

                chunks.append({
                    "source": "pdf_guide",
                    "page": str(page_num + 1),
                    "chunk_index": str(chunk_idx),
                    "item_no": item_no,
                    "text": chunk_text,
                })
                chunk_idx += 1
            start = end

    doc.close()
    print(f"[+] PDF 파싱 완료: {len(chunks)}개 텍스트 청크 생성")
    return chunks


# ──────────────────────────────────────────────
#  3) ChromaDB 벡터 DB 구축 및 검색
# ──────────────────────────────────────────────

class ISMSKnowledgeBase:
    """
    ISMS-P 지식베이스를 ChromaDB로 관리하는 클래스.
    초기 빌드 시 XLSX/PDF 데이터를 벡터화하여 저장하고,
    이후 쿼리를 통해 관련 규약을 검색합니다.
    """

    def __init__(self, persist_dir: str = CHROMA_PERSIST_DIR) -> None:
        self.persist_dir = persist_dir
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection: Optional[chromadb.Collection] = None

    def build_knowledge_base(self) -> None:
        """XLSX/PDF 에셋을 파싱하여 ChromaDB 컬렉션을 빌드합니다."""
        print("[*] ISMS-P 지식베이스 구축 중...")

        # 기존 컬렉션이 있으면 삭제 후 재생성
        try:
            self.client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass

        self.collection = self.client.create_collection(
            name=COLLECTION_NAME,
            metadata={"description": "ISMS-P 인증기준 지식베이스"},
        )

        documents: List[str] = []
        metadatas: List[Dict[str, str]] = []
        ids: List[str] = []

        # 3-1: XLSX 체크리스트 삽입
        xlsx_items = parse_xlsx_checklist()
        for i, item in enumerate(xlsx_items):
            doc_text = (
                f"[ISMS-P 점검항목] {item['item_no']} {item['item_name']}\n"
                f"분야: {item['field']}\n"
                f"상세내용: {item['detail']}\n"
                f"주요 확인사항: {item['check_point']}"
            )
            documents.append(doc_text)
            metadatas.append({
                "source": "xlsx_checklist",
                "item_no": item["item_no"],
                "field": item["field"],
                "sheet": item["sheet"],
            })
            ids.append(f"xlsx_{i}")

        # 3-2: PDF 가이드 청크 삽입
        pdf_chunks = parse_pdf_guide()
        for i, chunk in enumerate(pdf_chunks):
            documents.append(chunk["text"])
            metadatas.append({
                "source": "pdf_guide",
                "page": chunk["page"],
                "chunk_index": chunk["chunk_index"],
                "item_no": chunk.get("item_no", ""),
            })
            ids.append(f"pdf_{i}")

        # ChromaDB에 일괄 삽입 (배치 단위)
        if documents:
            batch_size = 500
            for start in range(0, len(documents), batch_size):
                end = min(start + batch_size, len(documents))
                self.collection.add(
                    documents=documents[start:end],
                    metadatas=metadatas[start:end],
                    ids=ids[start:end],
                )

        total = len(documents)
        print(f"[+] 지식베이스 구축 완료: 총 {total}개 문서 저장 (XLSX: {len(xlsx_items)}, PDF: {len(pdf_chunks)})")

    def load_collection(self) -> bool:
        """기존에 구축된 컬렉션을 로드합니다."""
        try:
            self.collection = self.client.get_collection(COLLECTION_NAME)
            count = self.collection.count()
            print(f"[+] 기존 ISMS-P 지식베이스 로드 완료 ({count}개 문서)")
            return True
        except Exception:
            return False

    def ensure_ready(self) -> None:
        """지식베이스가 준비되었는지 확인하고, 없으면 빌드합니다."""
        if not self.load_collection():
            self.build_knowledge_base()

    def search(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """
        쿼리와 관련된 ISMS-P 규약을 검색합니다.

        Args:
            query: 검색 쿼리 (예: "비밀번호 암호화", "세션 관리", "접근 통제")
            n_results: 반환할 최대 결과 수

        Returns:
            관련 규약 딕셔너리 리스트 (text, metadata, distance)
        """
        if not self.collection:
            self.ensure_ready()

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
        )

        search_results: List[Dict[str, Any]] = []
        if results and results["documents"]:
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            ):
                search_results.append({
                    "text": doc,
                    "metadata": meta,
                    "distance": dist,
                })

        return search_results

    def search_for_code_context(self, code_snippet: str, file_path: str) -> str:
        """
        코드 컨텍스트에 맞는 ISMS-P 규약을 검색하여 프롬프트에 삽입할 텍스트를 반환합니다.

        Args:
            code_snippet: 분석 대상 코드 조각
            file_path: 파일 경로 (보안 키워드 추출용)

        Returns:
            Agent 프롬프트에 삽입할 ISMS-P 참조 텍스트
        """
        # [개선] 단순 코드를 넣는 대신, 보안 키워드를 추출(Query Expansion)하여 검색 정확도를 높입니다.
        code_lower = code_snippet.lower()
        path_lower = file_path.lower()

        keywords = []
        if any(k in code_lower for k in ["password", "bcrypt", "hash", "crypto"]):
            keywords.extend(["비밀번호", "암호화", "해시", "비밀번호 일방향 암호화", "안전한 알고리즘"])
        if any(k in code_lower for k in ["login", "auth", "session"]) or "auth" in path_lower:
            keywords.extend(["인증", "세션", "식별", "접근 대상", "사용자 인증"])
        if any(k in code_lower for k in ["jwt", "token"]):
            keywords.extend(["토큰", "세션 탈취", "안전한 세션 관리"])
        if any(k in code_lower for k in ["user", "profile"]):
            keywords.extend(["개인정보", "사용자 식별", "개인정보 보호"])
        if any(k in code_lower for k in ["eval", "exec", "shell"]):
            keywords.extend(["입력 데이터 검증", "악의적 코드 실행", "취약점"])

        keyword_str = " ".join(list(set(keywords)))

        # 검색 쿼리 재구성: 관련 키워드 + 코드 일부 결합 (Hybrid Approach 대용)
        search_query = f"보안 규제 키워드: {keyword_str}\n관련 코드 컨텍스트: {code_snippet[:200]}"
        results = self.search(search_query, n_results=4)

        if not results:
            return ""

        lines = ["## ISMS-P 관련 규약 참조", ""]
        for i, r in enumerate(results, 1):
            lines.append(f"### 참조 {i}")
            lines.append(r["text"])
            if r["metadata"].get("item_no"):
                lines.append(f"(출처: ISMS-P {r['metadata']['item_no']})")
            elif r["metadata"].get("page"):
                lines.append(f"(출처: 안내서 {r['metadata']['page']}페이지)")
            lines.append("")

        return "\n".join(lines)
