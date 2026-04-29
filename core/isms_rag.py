"""
ISMS-P RAG(검색 증강 생성) 지식베이스 모듈.
ISMS-P 인증기준 XLSX/PDF 에셋을 파싱하여 ChromaDB 벡터 DB에 저장하고,
코드 분석 시 관련 규약을 검색하여 Agent에게 제공합니다.
"""
import os
import re
import pickle
from typing import Any, Dict, List, Optional

import openpyxl
import fitz  # PyMuPDF
import chromadb
from rank_bm25 import BM25Okapi

# 에셋 경로 (프로젝트 최상위 기준)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET_DIR = os.path.join(BASE_DIR, "asset")

XLSX_PATHS = [
    os.path.join(ASSET_DIR, "ISMS-P_인증기준_세부점검항목.xlsx"),
    os.path.join(ASSET_DIR, "(중기업)ISMS-P_인증기준_세부점검항목.xlsx"),
    os.path.join(ASSET_DIR, "(소기업)ISMS-P_인증기준_세부점검항목 (1).xlsx")
]

PDF_DOCS = [
    {"path": os.path.join(ASSET_DIR, "ISMS-P 인증기준 안내서(2023.11.23).pdf"), "type": "isms_p", "source": "pdf_isms_guide"},
    {"path": os.path.join(ASSET_DIR, "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"), "type": "tech_vuln", "source": "pdf_tech_vuln"},
    {"path": os.path.join(ASSET_DIR, "251222_OT_환경의_제로트러스트_적용_안내서.pdf"), "type": "ot_zt", "source": "pdf_ot_zt"}
]

# ChromaDB 로컬 저장 경로
CHROMA_PERSIST_DIR = os.path.join(BASE_DIR, ".chroma_db")
COLLECTION_NAME = "isms_p_knowledge"
BM25_INDEX_PATH = os.path.join(BASE_DIR, ".chroma_db", "bm25_index.pkl")

# ISMS-P 보안 용어 확장 사전 (Query Expansion용)
# 사용자 쿼리의 키워드를 감지하여 관련 ISMS-P 전문 용어로 확장
SECURITY_TERM_EXPANSION: Dict[str, List[str]] = {
    # 인증/접근제어
    "비밀번호": ["2.6.1", "암호화", "해시", "일방향", "안전한 알고리즘", "인증수단"],
    "암호화": ["2.7.1", "암호키 관리", "전송 시 암호화", "비밀번호 저장"],
    "세션": ["2.6.3", "세션 관리", "세션 타임아웃", "세션 탈취", "접근통제"],
    "인증": ["2.6.1", "2.6.2", "식별", "접근 대상", "사용자 인증", "인증수단"],
    "접근통제": ["2.6.1", "2.6.2", "2.6.3", "권한 관리", "접근권한"],
    # 데이터 보호
    "개인정보": ["3.1.1", "3.2.1", "개인정보 보호", "개인정보 수집", "동의"],
    "전송": ["2.7.1", "암호화 통신", "HTTPS", "TLS", "보호대책"],
    # 취약점/입력검증
    "입력값 검증": ["2.8.1", "입력 데이터 검증", "SQL 인젝션", "XSS", "악의적 코드"],
    "취약점": ["2.8.1", "2.11.1", "보안 취약점 점검", "보안 패치"],
    # 로그/모니터링
    "로그": ["2.9.1", "로그 관리", "추적성 확보", "접근기록"],
    "모니터링": ["2.9.2", "실시간 모니터링", "침해사고 대응"],
    # 네트워크/시스템
    "네트워크": ["2.4.1", "2.4.2", "네트워크 보안", "방화벽", "네트워크 접근"],
    "서버": ["2.4.3", "서버 보안", "정보시스템 보안"],
}


# ──────────────────────────────────────────────
#  1) XLSX 파싱: 세부점검항목 구조화
# ──────────────────────────────────────────────

def parse_xlsx_checklist(xlsx_path: str) -> List[Dict[str, str]]:
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
#  2) PDF 파싱: 계층적 구조 파싱 + 스마트 청킹
# ──────────────────────────────────────────────

# 폰트 크기 기반 헤더 레벨 임계값 (PDF 구조 분석 결과 기반)
FONT_SIZE_H1 = 18.0   # 대분류 (예: "2 보호대책 요구사항")
FONT_SIZE_H2 = 14.0   # 중분류 (예: "2.1. 정책, 조직, 자산 관리")
FONT_SIZE_H3 = 11.0   # 소분류/조항 (예: "2.1.1 보안정책 수립")
MAX_CHUNK_CHARS = 1500 # 청크 최대 문자 수 (약 500~700토큰)


def _table_to_markdown(table_data: List[List[Optional[str]]]) -> str:
    """fitz에서 추출한 표 데이터를 마크다운 테이블로 변환합니다."""
    if not table_data or not table_data[0]:
        return ""

    # None을 빈 문자열로 치환, 개행을 공백으로 정리
    cleaned = []
    for row in table_data:
        cleaned.append([str(cell).replace("\n", " ").strip() if cell else "" for cell in row])

    col_count = max(len(r) for r in cleaned)
    # 열 수 맞추기
    for row in cleaned:
        while len(row) < col_count:
            row.append("")

    header = cleaned[0]
    lines = ["| " + " | ".join(header) + " |"]
    lines.append("| " + " | ".join(["---"] * col_count) + " |")
    for row in cleaned[1:]:
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)


def _extract_structured_blocks(doc) -> List[Dict[str, Any]]:
    """
    Phase 1: PDF 전체를 순회하며 폰트 크기 기반으로 헤더/본문/표를 구분하여
    구조화된 블록 리스트를 생성합니다.

    Returns:
        [{"type": "header"|"text"|"table", "content": str,
          "font_size": float, "page": int}, ...]
    """
    blocks: List[Dict[str, Any]] = []

    for page_num in range(len(doc)):
        page = doc[page_num]

        # 표 영역 좌표 수집 (본문 텍스트와 중복 제거용)
        table_rects = []
        try:
            page_tables = page.find_tables()
            for tbl in page_tables.tables:
                table_rects.append(fitz.Rect(tbl.bbox))
                md = _table_to_markdown(tbl.extract())
                if md:
                    blocks.append({
                        "type": "table",
                        "content": md,
                        "font_size": 0,
                        "page": page_num + 1,
                    })
        except Exception:
            pass

        # 텍스트를 라인 단위로 추출 (표 영역 제외)
        raw_blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
        for b in raw_blocks:
            if b["type"] != 0:  # 이미지 등 비텍스트 블록 스킵
                continue

            # 블록 좌표가 표 영역과 겹치면 스킵
            block_rect = fitz.Rect(b["bbox"])
            in_table = any(block_rect.intersects(tr) for tr in table_rects)
            if in_table:
                continue

            # 라인 단위로 분석하여 헤더/본문을 개별 판별
            for line in b["lines"]:
                line_font_size = max(span["size"] for span in line["spans"])
                line_text = "".join(span["text"] for span in line["spans"]).strip()

                if not line_text or len(line_text) < 2:
                    continue

                # 헤더 판별 (라인 단위)
                line_type = "text"
                if line_font_size >= FONT_SIZE_H1:
                    line_type = "header"
                elif line_font_size >= FONT_SIZE_H2:
                    line_type = "header"
                elif line_font_size >= FONT_SIZE_H3:
                    # 조항 번호 패턴이 있으면 헤더로 판별
                    if re.search(r'\d+\.\d+\.\d+', line_text):
                        line_type = "header"

                blocks.append({
                    "type": line_type,
                    "content": line_text,
                    "font_size": line_font_size,
                    "page": page_num + 1,
                })

    return blocks


def _build_hierarchical_nodes_isms(blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 2: 블록 리스트를 순회하며 계층적 메타데이터를 추적하고,
    조항 단위의 노드를 생성합니다.

    각 노드는 {"text": str, "metadata": {...}, "type": "text"|"table"} 형태입니다.
    """
    nodes: List[Dict[str, Any]] = []

    # 상태 추적기: 현재 읽고 있는 위치의 계층 정보
    current_chapter = ""   # 대분류 (예: "2. 보호대책 요구사항")
    current_section = ""   # 중분류 (예: "2.1. 정책, 조직, 자산 관리")
    current_article = ""   # 소분류 (예: "2.1.1 보안정책 수립")
    current_article_no = "" # 조항 번호만 (예: "2.1.1")

    # 현재 조항에 누적 중인 텍스트 버퍼
    text_buffer: List[str] = []
    buffer_pages: List[int] = []

    def _flush_buffer():
        """버퍼에 쌓인 텍스트를 하나의 노드로 확정합니다."""
        if not text_buffer:
            return
        combined = "\n".join(text_buffer).strip()
        if combined:
            nodes.append({
                "text": combined,
                "type": "text",
                "metadata": {
                    "source": "pdf_guide",
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": current_article,
                    "article_no": current_article_no,
                    "pages": f"{min(buffer_pages)}-{max(buffer_pages)}" if buffer_pages else "",
                },
            })
        text_buffer.clear()
        buffer_pages.clear()

    for block in blocks:
        content = block["content"]
        page = block["page"]

        if block["type"] == "header":
            font_size = block["font_size"]

            # 대분류 헤더 감지 (폰트 18+)
            if font_size >= FONT_SIZE_H1:
                _flush_buffer()
                current_chapter = content.replace("\n", " ").strip()
                current_section = ""
                current_article = ""
                current_article_no = ""
                continue

            # 중분류 헤더 감지 (폰트 14+)
            if font_size >= FONT_SIZE_H2:
                _flush_buffer()
                current_section = content.replace("\n", " ").strip()
                current_article = ""
                current_article_no = ""
                continue

            # 조항 번호 헤더 감지 (예: "인증기준\n2.1.1 보안정책 수립")
            article_match = re.search(r'(\d+\.\d+\.\d+)\s*(.*)', content)
            if article_match:
                _flush_buffer()
                current_article_no = article_match.group(1)
                # 조항 번호부터의 텍스트만 추출하여 article 이름으로 사용
                current_article = article_match.group(0).replace("\n", " ").strip()
                continue

        # 표 블록: 표 내에서 조항 번호를 추출하고 메타데이터 업데이트
        if block["type"] == "table":
            # 표 안에 조항 번호가 포함되어 있으면 상태 업데이트
            table_article_match = re.search(r'(\d+\.\d+\.\d+)\s*([\w\s가-힣]*)', content)
            if table_article_match:
                _flush_buffer()
                current_article_no = table_article_match.group(1)
                article_name = table_article_match.group(2).strip()
                current_article = f"{current_article_no} {article_name}" if article_name else current_article_no

            nodes.append({
                "text": content,
                "type": "table",
                "metadata": {
                    "source": "pdf_guide",
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": current_article,
                    "article_no": current_article_no,
                    "pages": str(page),
                },
            })
            continue

        # 일반 텍스트: 현재 조항 버퍼에 누적
        text_buffer.append(content)
        buffer_pages.append(page)

    # 마지막 버퍼 확정
    _flush_buffer()
    return nodes


def _build_hierarchical_nodes_tech_vuln(blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    주요정보통신기반시설 기술적 취약점 가이드용 파서.
    U-01 등 고유 항목 코드 중심 구조 파싱.
    """
    nodes: List[Dict[str, Any]] = []
    current_chapter = ""
    current_section = ""
    current_article = ""
    current_article_no = ""
    
    text_buffer: List[str] = []
    buffer_pages: List[int] = []

    def _flush_buffer():
        if not text_buffer:
            return
        combined = "\n".join(text_buffer).strip()
        if combined:
            nodes.append({
                "text": combined,
                "type": "text",
                "metadata": {
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": current_article,
                    "article_no": current_article_no,
                    "pages": f"{min(buffer_pages)}-{max(buffer_pages)}" if buffer_pages else "",
                },
            })
        text_buffer.clear()
        buffer_pages.clear()

    for block in blocks:
        content = block["content"]
        page = block["page"]
        
        # U-01 등 항목코드 감지
        u_match = re.search(r'(U-\d+)\s*(.*)', content, re.IGNORECASE)
        if u_match and block["font_size"] >= FONT_SIZE_H3:
            _flush_buffer()
            current_article_no = u_match.group(1).upper()
            current_article = content.replace("\n", " ").strip()
            continue
            
        if block["type"] == "header" and not u_match:
            font_size = block["font_size"]
            if font_size >= FONT_SIZE_H1:
                _flush_buffer()
                current_chapter = content.replace("\n", " ").strip()
                current_section = ""
                continue
            if font_size >= FONT_SIZE_H2:
                _flush_buffer()
                current_section = content.replace("\n", " ").strip()
                continue
                
        if block["type"] == "table":
            nodes.append({
                "text": content,
                "type": "table",
                "metadata": {
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": current_article,
                    "article_no": current_article_no,
                    "pages": str(page),
                },
            })
            continue

        text_buffer.append(content)
        buffer_pages.append(page)

    _flush_buffer()
    return nodes


def _build_hierarchical_nodes_ot_zt(blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    OT 환경 제로트러스트 안내서용 파서.
    장(Chapter), 절(Section) 중심의 서술형 구조 파싱.
    """
    nodes: List[Dict[str, Any]] = []
    current_chapter = ""
    current_section = ""
    
    text_buffer: List[str] = []
    buffer_pages: List[int] = []

    def _flush_buffer():
        if not text_buffer:
            return
        combined = "\n".join(text_buffer).strip()
        if combined:
            nodes.append({
                "text": combined,
                "type": "text",
                "metadata": {
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": "",
                    "article_no": "",
                    "pages": f"{min(buffer_pages)}-{max(buffer_pages)}" if buffer_pages else "",
                },
            })
        text_buffer.clear()
        buffer_pages.clear()

    for block in blocks:
        content = block["content"]
        page = block["page"]
        
        if block["type"] == "header":
            font_size = block["font_size"]
            if font_size >= FONT_SIZE_H1 or re.match(r'^제\s*\d+\s*장', content):
                _flush_buffer()
                current_chapter = content.replace("\n", " ").strip()
                current_section = ""
                continue
            if font_size >= FONT_SIZE_H2 or re.match(r'^\d+\.\d+\s+', content) or re.match(r'^제\s*\d+\s*절', content):
                _flush_buffer()
                current_section = content.replace("\n", " ").strip()
                continue
                
        if block["type"] == "table":
            nodes.append({
                "text": content,
                "type": "table",
                "metadata": {
                    "chapter": current_chapter,
                    "section": current_section,
                    "article": "",
                    "article_no": "",
                    "pages": str(page),
                },
            })
            continue

        text_buffer.append(content)
        buffer_pages.append(page)

    _flush_buffer()
    return nodes


def _split_oversized_nodes(
    nodes: List[Dict[str, Any]],
    max_chars: int = MAX_CHUNK_CHARS,
) -> List[Dict[str, Any]]:
    """
    Phase 3: 노드가 max_chars를 초과하면 RecursiveCharacterTextSplitter로 재분할합니다.
    자식 청크는 부모 메타데이터를 상속받습니다.
    표 노드의 경우 컬럼 헤더를 보존합니다.
    """
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=max_chars,
        chunk_overlap=200,
        separators=["\n\n", "\n", ". ", " "],
    )

    final_chunks: List[Dict[str, Any]] = []

    for node in nodes:
        text = node["text"]
        meta = node["metadata"]

        if len(text) <= max_chars:
            final_chunks.append(node)
            continue

        if node["type"] == "table":
            # 표 분할 시 컬럼 헤더(첫 2줄) 보존
            lines = text.split("\n")
            if len(lines) >= 2:
                header_lines = "\n".join(lines[:2])
                data_lines = lines[2:]

                # 데이터 행들을 max_chars 이하로 묶기
                current_chunk_lines = []
                current_len = len(header_lines)
                chunk_idx = 0

                for line in data_lines:
                    if current_len + len(line) + 1 > max_chars and current_chunk_lines:
                        chunk_text = header_lines + "\n" + "\n".join(current_chunk_lines)
                        child_meta = {**meta, "chunk_index": str(chunk_idx)}
                        final_chunks.append({"text": chunk_text, "type": "table", "metadata": child_meta})
                        current_chunk_lines = []
                        current_len = len(header_lines)
                        chunk_idx += 1

                    current_chunk_lines.append(line)
                    current_len += len(line) + 1

                if current_chunk_lines:
                    chunk_text = header_lines + "\n" + "\n".join(current_chunk_lines)
                    child_meta = {**meta, "chunk_index": str(chunk_idx)}
                    final_chunks.append({"text": chunk_text, "type": "table", "metadata": child_meta})
            else:
                final_chunks.append(node)
        else:
            # 텍스트 노드: RecursiveCharacterTextSplitter로 분할
            sub_texts = splitter.split_text(text)
            for idx, sub in enumerate(sub_texts):
                child_meta = {**meta, "chunk_index": str(idx)}
                final_chunks.append({"text": sub, "type": "text", "metadata": child_meta})

    return final_chunks


def parse_pdf_file(pdf_path: str, doc_type: str = "isms_p", source_name: str = "pdf_guide") -> List[Dict[str, Any]]:
    """
    다양한 형식의 보안 안내서 PDF를 계층적으로 파싱합니다.
    doc_type에 따라 다른 노드 빌더를 사용합니다.
    """
    if not os.path.exists(pdf_path):
        print(f"[!] PDF 파일을 찾을 수 없습니다: {pdf_path}")
        return []

    doc = fitz.open(pdf_path)

    print(f"[*] Phase 1: {os.path.basename(pdf_path)} 구조적 파싱 중...")
    blocks = _extract_structured_blocks(doc)
    print(f"    → {len(blocks)}개 블록 추출")

    print("[*] Phase 2: 계층적 메타데이터 추적 및 노드 생성 중...")
    if doc_type == "tech_vuln":
        nodes = _build_hierarchical_nodes_tech_vuln(blocks)
    elif doc_type == "ot_zt":
        nodes = _build_hierarchical_nodes_ot_zt(blocks)
    else:
        nodes = _build_hierarchical_nodes_isms(blocks)
    
    # source metadata 주입
    for node in nodes:
        node["metadata"]["source"] = source_name
        
    print(f"    → {len(nodes)}개 노드 생성")

    print("[*] Phase 3: 초과 크기 노드 분할 중...")
    final_chunks = _split_oversized_nodes(nodes)
    print(f"    → 최종 {len(final_chunks)}개 청크 생성")

    doc.close()

    # 통계 출력
    text_count = sum(1 for c in final_chunks if c["type"] == "text")
    table_count = sum(1 for c in final_chunks if c["type"] == "table")
    with_article = sum(1 for c in final_chunks if c["metadata"].get("article_no"))
    print(f"[+] PDF 파싱 완료: 텍스트 {text_count}개, 표 {table_count}개 (조항 매핑: {with_article}개)")

    return final_chunks


# ──────────────────────────────────────────────
#  3) ChromaDB 벡터 DB 구축 및 검색
# ──────────────────────────────────────────────

def _tokenize_korean(text: str) -> List[str]:
    """
    한국어 텍스트를 BM25용 토큰으로 분할합니다.
    형태소 분석기 없이 공백 분리 + 조항 번호 보존 + 특수문자 제거를 수행합니다.
    """
    # 조항 번호 패턴을 별도 토큰으로 보존 (예: "2.6.1")
    article_tokens = re.findall(r'\d+\.\d+\.\d+', text)
    # 취약점 항목 코드 보존 (예: "U-01", "U-12")
    u_code_tokens = re.findall(r'U-\d+', text, re.IGNORECASE)
    # 일반 텍스트: 특수문자 제거 (하이픈은 보존) 후 공백 분리
    cleaned = re.sub(r'[^\w가-힣\s-]', ' ', text)
    word_tokens = [t for t in cleaned.split() if len(t) >= 2]
    return article_tokens + u_code_tokens + word_tokens


class ISMSKnowledgeBase:
    """
    ISMS-P 지식베이스를 ChromaDB + BM25 하이브리드로 관리하는 클래스.
    초기 빌드 시 XLSX/PDF 데이터를 벡터 DB와 BM25 인덱스에 동시 저장하고,
    검색 시 RRF(Reciprocal Rank Fusion)로 두 결과를 합산합니다.
    """

    def __init__(self, persist_dir: str = CHROMA_PERSIST_DIR) -> None:
        self.persist_dir = persist_dir
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection: Optional[chromadb.Collection] = None
        # BM25 인덱스 관련
        self.bm25: Optional[BM25Okapi] = None
        self._bm25_documents: List[str] = []     # 원본 문서 텍스트
        self._bm25_metadatas: List[Dict] = []     # 메타데이터
        self._bm25_ids: List[str] = []            # 문서 ID

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

        # 3-1: XLSX 체크리스트 삽입 (복수 파일)
        for path in XLSX_PATHS:
            if not os.path.exists(path):
                continue
            xlsx_items = parse_xlsx_checklist(path)
            base_name = os.path.basename(path)
            for i, item in enumerate(xlsx_items):
                doc_text = (
                    f"[{base_name} 점검항목] {item['item_no']} {item['item_name']}\n"
                    f"분야: {item['field']}\n"
                    f"상세내용: {item['detail']}\n"
                    f"주요 확인사항: {item['check_point']}"
                )
                documents.append(doc_text)
                metadatas.append({
                    "source": "xlsx_checklist",
                    "file_name": base_name,
                    "item_no": item["item_no"],
                    "field": item["field"],
                    "sheet": item["sheet"],
                })
                ids.append(f"xlsx_{base_name}_{i}")

        # 3-2: 복수의 PDF 가이드 청크 삽입
        for pdf_info in PDF_DOCS:
            path = pdf_info["path"]
            if not os.path.exists(path):
                continue
            pdf_chunks = parse_pdf_file(path, doc_type=pdf_info["type"], source_name=pdf_info["source"])
            base_name = os.path.basename(path)
            for i, chunk in enumerate(pdf_chunks):
                meta = chunk["metadata"]
                prefix_parts = []
                if meta.get("article_no") and meta.get("article_no").startswith("U-"):
                    prefix_parts.append(f"[{base_name} {meta['article_no']}]")
                elif meta.get("article"):
                    prefix_parts.append(f"[{base_name} {meta['article']}]")
                elif meta.get("section"):
                    prefix_parts.append(f"[{base_name} {meta['section']}]")
                elif meta.get("chapter"):
                    prefix_parts.append(f"[{base_name} {meta['chapter']}]")

                prefix = " ".join(prefix_parts)
                doc_text = f"{prefix}\n{chunk['text']}" if prefix else chunk["text"]

                documents.append(doc_text)
                metadatas.append({
                    "source": meta.get("source", "pdf_guide"),
                    "file_name": base_name,
                    "chapter": meta.get("chapter", ""),
                    "section": meta.get("section", ""),
                    "article": meta.get("article", ""),
                    "article_no": meta.get("article_no", ""),
                    "pages": meta.get("pages", ""),
                    "chunk_type": chunk.get("type", "text"),
                })
                ids.append(f"pdf_{pdf_info['type']}_{i}")


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

        # BM25 인덱스 빌드
        print("[*] BM25 키워드 인덱스 구축 중...")
        tokenized_corpus = [_tokenize_korean(doc) for doc in documents]
        self.bm25 = BM25Okapi(tokenized_corpus)
        self._bm25_documents = documents
        self._bm25_metadatas = metadatas
        self._bm25_ids = ids

        # BM25 인덱스 영속화 (pickle)
        bm25_data = {
            "bm25": self.bm25,
            "documents": documents,
            "metadatas": metadatas,
            "ids": ids,
        }
        os.makedirs(os.path.dirname(BM25_INDEX_PATH), exist_ok=True)
        with open(BM25_INDEX_PATH, "wb") as f:
            pickle.dump(bm25_data, f)
        print(f"[+] BM25 인덱스 저장 완료: {len(documents)}개 문서")

        total = len(documents)
        print(f"[+] 지식베이스 구축 완료: 총 {total}개 문서 저장 (XLSX: {len(xlsx_items)}, PDF: {len(pdf_chunks)})")

    def load_collection(self) -> bool:
        """기존에 구축된 ChromaDB 컬렉션과 BM25 인덱스를 로드합니다."""
        try:
            self.collection = self.client.get_collection(COLLECTION_NAME)
            count = self.collection.count()
            print(f"[+] 기존 ISMS-P 지식베이스 로드 완료 ({count}개 문서)")

            # BM25 인덱스 로드
            if os.path.exists(BM25_INDEX_PATH):
                with open(BM25_INDEX_PATH, "rb") as f:
                    bm25_data = pickle.load(f)
                self.bm25 = bm25_data["bm25"]
                self._bm25_documents = bm25_data["documents"]
                self._bm25_metadatas = bm25_data["metadatas"]
                self._bm25_ids = bm25_data["ids"]
                print(f"[+] BM25 인덱스 로드 완료 ({len(self._bm25_documents)}개 문서)")
            else:
                print("[!] BM25 인덱스 없음 - 재구축 필요")
                return False

            return True
        except Exception:
            return False

    def ensure_ready(self) -> None:
        """지식베이스가 준비되었는지 확인하고, 없으면 빌드합니다."""
        if not self.load_collection():
            self.build_knowledge_base()

    def _search_vector(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """ChromaDB 벡터 검색 (의미 기반)."""
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
        )
        search_results: List[Dict[str, Any]] = []
        if results and results["documents"]:
            for doc, meta, doc_id in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["ids"][0],
            ):
                search_results.append({
                    "text": doc,
                    "metadata": meta,
                    "id": doc_id,
                })
        return search_results

    def _search_bm25(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """BM25 키워드 검색."""
        if not self.bm25:
            return []
        tokens = _tokenize_korean(query)
        scores = self.bm25.get_scores(tokens)

        # 상위 n_results개 인덱스 추출
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n_results]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:  # BM25 점수가 0보다 큰 것만
                results.append({
                    "text": self._bm25_documents[idx],
                    "metadata": self._bm25_metadatas[idx],
                    "id": self._bm25_ids[idx],
                    "bm25_score": float(scores[idx]),
                })
        return results

    def search(self, query: str, n_results: int = 5, vector_weight: float = 0.4, bm25_weight: float = 0.6) -> List[Dict[str, Any]]:
        """
        하이브리드 검색: 벡터(의미) + BM25(키워드) 결과를 RRF로 합산합니다.

        Args:
            query: 검색 쿼리
            n_results: 반환할 최대 결과 수
            vector_weight: 벡터 검색 가중치 (기본 0.4)
            bm25_weight: BM25 검색 가중치 (기본 0.6, ISMS-P는 키워드 매칭이 중요)

        Returns:
            RRF 점수 기반 정렬된 검색 결과 리스트
        """
        if not self.collection:
            self.ensure_ready()

        # Query Expansion: 보안 용어 사전으로 쿼리 확장
        expanded_terms: List[str] = []
        query_lower = query.lower()
        for keyword, expansions in SECURITY_TERM_EXPANSION.items():
            if keyword in query_lower or keyword in query:
                expanded_terms.extend(expansions)
        # 중복 제거 후 쿼리에 붙이기
        if expanded_terms:
            expansion_str = " ".join(list(dict.fromkeys(expanded_terms)))
            expanded_query = f"{query} {expansion_str}"
        else:
            expanded_query = query

        # 각 검색 엔진에서 후보 확보 (3배수 검색)
        fetch_count = n_results * 3
        vector_results = self._search_vector(expanded_query, n_results=fetch_count)
        bm25_results = self._search_bm25(expanded_query, n_results=fetch_count)

        # RRF(Reciprocal Rank Fusion) 합산
        # score = Σ weight / (k + rank)  (k=60이 일반적)
        k = 60
        rrf_scores: Dict[str, float] = {}  # doc_id → RRF 점수
        doc_map: Dict[str, Dict[str, Any]] = {}  # doc_id → 문서 데이터

        for rank, result in enumerate(vector_results):
            doc_id = result["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + vector_weight / (k + rank + 1)
            doc_map[doc_id] = result

        for rank, result in enumerate(bm25_results):
            doc_id = result["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + bm25_weight / (k + rank + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = result

        # RRF 점수 기준 내림차순 정렬
        sorted_ids = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)

        final_results: List[Dict[str, Any]] = []
        for doc_id in sorted_ids[:n_results]:
            entry = doc_map[doc_id]
            final_results.append({
                "text": entry["text"],
                "metadata": entry["metadata"],
                "rrf_score": rrf_scores[doc_id],
            })

        return final_results

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
            meta = r["metadata"]
            if meta.get("article_no"):
                lines.append(f"(출처: ISMS-P {meta['article_no']} - {meta.get('article', '')})")
            elif meta.get("item_no"):
                lines.append(f"(출처: ISMS-P {meta['item_no']})")
            elif meta.get("pages"):
                lines.append(f"(출처: 안내서 {meta['pages']}페이지)")
            lines.append("")

        return "\n".join(lines)
