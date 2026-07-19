"""Agentic-SAST-Guardian CLI 진입점."""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv

from core.pipeline import PipelineBusyError, run_pipeline


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}초"
    minutes = int(seconds // 60)
    return f"{minutes}분 {seconds % 60:.1f}초"


def _print_progress(phase: str, message: str, _progress: float) -> None:
    print(f"[{phase}] {message}")


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Agentic-SAST-Guardian: AI 기반 정적 보안 분석 도구")
    parser.add_argument("--target", required=True, help="스캔할 대상 디렉토리 경로")
    args = parser.parse_args()

    try:
        result = run_pipeline(args.target, progress_callback=_print_progress)
    except (ValueError, OSError, PipelineBusyError) as exc:
        print(f"[!] 분석을 시작할 수 없습니다: {type(exc).__name__}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] 분석 중 오류가 발생했습니다: {type(exc).__name__}", file=sys.stderr)
        return 1

    print("=" * 60)
    print(f"[+] 분석 완료: {len(result.findings)}개 finding, {_fmt_elapsed(result.elapsed_seconds)}")
    print(f"    Run ID: {result.run_id}")
    print(f"    PDF/HTML: {result.artifacts.pdf_or_html}")
    print(f"    XLSX: {result.artifacts.xlsx}")
    print(f"    JSON: {result.artifacts.json}")
    if result.partial:
        print("[!] 실행 한도에 도달해 부분 결과가 생성되었습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
