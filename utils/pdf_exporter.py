"""
PDF 리포트 변환 모듈.
Markdown 리포트를 전문적인 디자인의 HTML로 변환한 뒤 PDF로 출력합니다.
wkhtmltopdf가 설치되지 않은 환경에서는 HTML 파일로 폴백합니다.
"""
import os
import markdown
from typing import Optional


REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;700&display=swap');

:root {
    --primary: #4f46e5;
    --primary-bg: #f5f3ff;
    --critical: #e11d48;
    --high: #ea580c;
    --medium: #d97706;
    --low: #059669;
    --info: #2563eb;
    --bg-main: #f8fafc;
    --surface: #ffffff;
    --text-main: #1e293b;
    --text-muted: #64748b;
    --border: #e2e8f0;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Inter', 'Noto Sans KR', sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: var(--text-main);
    background: var(--bg-main);
    padding: 60px 80px;
    max-width: 1000px;
    margin: 0 auto;
}

/* Typography */
h1 {
    font-family: 'Outfit', sans-serif;
    font-size: 42px;
    font-weight: 700;
    color: var(--primary);
    margin-bottom: 8px;
    letter-spacing: -0.02em;
}

h2 {
    font-family: 'Outfit', sans-serif;
    font-size: 24px;
    font-weight: 700;
    margin-top: 48px;
    margin-bottom: 24px;
    color: #0f172a;
    border-bottom: 2px solid var(--border);
    padding-bottom: 8px;
}

h3 {
    font-size: 18px;
    font-weight: 600;
    margin-top: 32px;
    margin-bottom: 12px;
    color: #1e293b;
}

p { margin-bottom: 12px; }
.report-meta { color: var(--text-muted); font-size: 14px; margin-bottom: 40px; }

/* Dashboard & Cards */
.dashboard {
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
}

.score-card {
    flex: 1.5;
    background: var(--surface);
    padding: 24px;
    border-radius: 16px;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    border: 1px solid var(--border);
    text-align: center;
}

.score-label { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; }
.score-value { font-size: 64px; font-weight: 800; line-height: 1; margin: 12px 0; font-family: 'Outfit', sans-serif; }
.score-bar-bg { background: #f1f5f9; height: 10px; border-radius: 5px; overflow: hidden; }
.score-bar-fill { height: 100%; border-radius: 5px; transition: width 0.5s ease; }

.stats-grid { flex: 2; display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
.stat-card {
    padding: 16px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: var(--surface);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-label { font-size: 11px; font-weight: 700; color: var(--text-muted); }
.stat-count { font-size: 28px; font-weight: 700; margin-top: 4px; }

.stat-card.critical { border-left: 4px solid var(--critical); color: var(--critical); }
.stat-card.high { border-left: 4px solid var(--high); color: var(--high); }
.stat-card.medium { border-left: 4px solid var(--medium); color: var(--medium); }
.stat-card.info { border-left: 4px solid var(--info); color: var(--info); }

/* Table Style */
table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 20px 0;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
}

th {
    background: #f8fafc;
    color: #475569;
    font-weight: 600;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: #fff;
    vertical-align: middle;
}

tr:last-child td { border-bottom: none; }

/* Code blocks */
blockquote {
    border-left: 4px solid var(--primary);
    background: #f1f5f9;
    padding: 16px 20px;
    margin: 16px 0;
    border-radius: 0 8px 8px 0;
    color: #334155;
    font-style: italic;
}

pre {
    background: #1e293b;
    color: #f8fafc;
    padding: 20px;
    border-radius: 12px;
    overflow-x: auto;
    margin: 16px 0;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 13px;
    box-shadow: inset 0 2px 4px 0 rgb(0 0 0 / 0.06);
}

code {
    background: #f1f5f9;
    color: var(--primary);
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 500;
    font-family: monospace;
}

pre code { background: transparent; color: inherit; padding: 0; }

/* Responsive & Print */
.page-break { page-break-after: always; }

@media print {
    body { background: #fff; padding: 0; }
    .stat-card { border: 1px solid #ddd; page-break-inside: avoid; }
    h2, h3 { page-break-after: avoid; }
    pre, table { page-break-inside: avoid; }
}

@page {
    size: A4;
    margin: 20mm;
}
"""


def markdown_to_html(md_content: str) -> str:
    """Markdown 텍스트를 스타일이 적용된 HTML 문서로 변환합니다."""
    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "nl2br"],
    )

    # f-string 대신 .replace()를 사용하여 CSS 내부의 중괄호 충돌을 방지합니다.
    html_doc = """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agentic-SAST-Guardian 보안 분석 리포트</title>
    <style>REPORT_CSS_PLACEHOLDER</style>
</head>
<body>
HTML_BODY_PLACEHOLDER
</body>
</html>"""
    
    html_doc = html_doc.replace("REPORT_CSS_PLACEHOLDER", REPORT_CSS)
    html_doc = html_doc.replace("HTML_BODY_PLACEHOLDER", html_body)
    
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
