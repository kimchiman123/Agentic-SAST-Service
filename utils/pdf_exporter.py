"""
PDF 리포트 변환 모듈.
Markdown 리포트를 전문적인 디자인의 HTML로 변환한 뒤 PDF로 출력합니다.
wkhtmltopdf가 설치되지 않은 환경에서는 HTML 파일로 폴백합니다.
"""
import os
import markdown
from typing import Optional


# 전문 보안 리포트용 CSS 스타일
REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@300;400;500;700&display=swap');

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Noto Sans KR', 'Malgun Gothic', sans-serif;
    font-size: 13px;
    line-height: 1.7;
    color: #222222;
    background: #ffffff;
    padding: 40px 50px;
    max-width: 900px;
    margin: 0 auto;
}

h1 {
    font-size: 24px;
    font-weight: 700;
    color: #000000;
    border-bottom: 3px solid #000000;
    padding-bottom: 12px;
    margin-bottom: 20px;
}

h2 {
    font-size: 18px;
    font-weight: 700;
    color: #111111;
    margin-top: 30px;
    margin-bottom: 12px;
    padding: 8px 12px;
    background: #f4f4f4;
    border-left: 4px solid #333333;
    border-radius: 0 4px 4px 0;
}

h3 {
    font-size: 15px;
    font-weight: 600;
    color: #000000;
    margin-top: 20px;
    margin-bottom: 8px;
}

p { margin: 6px 0; }
strong { font-weight: 600; }

ul, ol {
    margin: 6px 0 6px 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 12.5px;
}

th {
    background: #000000;
    color: #ffffff;
    font-weight: 600;
    padding: 10px 12px;
    text-align: left;
    border: 1px solid #000000;
}

td {
    padding: 8px 12px;
    border: 1px solid #cccccc;
}

tr:nth-child(even) td {
    background: #fafafa;
}

blockquote {
    border-left: 3px solid #666666;
    background: #f9f9f9;
    padding: 10px 16px;
    margin: 8px 0;
    font-size: 12.5px;
    color: #555555;
    border-radius: 0 4px 4px 0;
}

code {
    background: #eeeeee;
    padding: 2px 5px;
    border-radius: 3px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: #000000;
    font-weight: 500;
}

pre {
    background: #111111;
    color: #f1f1f1;
    padding: 14px 16px;
    border-radius: 6px;
    overflow-x: auto;
    margin: 8px 0;
    font-size: 11.5px;
    line-height: 1.5;
}

pre code {
    background: transparent;
    color: inherit;
    padding: 0;
    font-weight: normal;
}

hr {
    border: none;
    border-top: 1px solid #cccccc;
    margin: 24px 0;
}

em {
    color: #666666;
    font-size: 12px;
}

/* 심각도 색상 - 흑백 톤 유지 */
.severity-critical { color: #000000; font-weight: 800; text-decoration: underline; }
.severity-high { color: #333333; font-weight: 700; }
.severity-medium { color: #555555; font-weight: 600; }
.severity-low { color: #777777; }

/* 페이지 헤더 */
.report-header {
    text-align: center;
    padding: 20px 0 30px 0;
    border-bottom: 2px solid #000000;
    margin-bottom: 30px;
}

.report-header h1 {
    border-bottom: none;
    padding-bottom: 0;
    font-size: 26px;
}

/* 인쇄 최적화 */
@media print {
    body { padding: 20px 30px; }
    h2 { page-break-after: avoid; }
    h3 { page-break-after: avoid; }
    pre { page-break-inside: avoid; }
    table { page-break-inside: avoid; }
}

@page {
    size: A4;
    margin: 15mm 20mm;
}
"""


def markdown_to_html(md_content: str) -> str:
    """Markdown 텍스트를 스타일이 적용된 HTML 문서로 변환합니다."""
    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "nl2br"],
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agentic-SAST-Guardian 보안 분석 리포트</title>
    <style>{REPORT_CSS}</style>
</head>
<body>
{html_body}
</body>
</html>"""
    return html_doc


def export_pdf(md_content: str, output_path: str) -> str:
    """
    Markdown 리포트를 PDF로 변환하여 저장합니다.
    wkhtmltopdf가 없으면 HTML로 폴백합니다.

    Args:
        md_content: Markdown 형식의 리포트 텍스트
        output_path: 저장할 PDF 파일 경로 (확장자 포함)

    Returns:
        실제 저장된 파일 경로 (PDF 또는 HTML)
    """
    html_content = markdown_to_html(md_content)

    # PDF 변환 시도 (pdfkit + wkhtmltopdf)
    pdf_path = _try_pdfkit_export(html_content, output_path)
    if pdf_path:
        return pdf_path

    # 폴백: HTML 파일로 저장 (브라우저에서 열어 인쇄 가능)
    html_path = output_path.rsplit(".", 1)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print("[*] wkhtmltopdf가 설치되지 않아 HTML로 저장되었습니다.")
    print("    브라우저에서 열어 Ctrl+P로 PDF 인쇄가 가능합니다.")
    return html_path


def _try_pdfkit_export(html_content: str, output_path: str) -> Optional[str]:
    """pdfkit을 이용한 PDF 변환을 시도합니다."""
    try:
        import pdfkit

        options = {
            "encoding": "UTF-8",
            "page-size": "A4",
            "margin-top": "15mm",
            "margin-right": "20mm",
            "margin-bottom": "15mm",
            "margin-left": "20mm",
            "enable-local-file-access": "",
            "no-outline": None,
        }

        pdfkit.from_string(html_content, output_path, options=options)
        return output_path

    except OSError:
        # wkhtmltopdf 바이너리가 없는 경우
        return None
    except Exception as e:
        print(f"[!] PDF 변환 중 오류 발생: {e}")
        return None
