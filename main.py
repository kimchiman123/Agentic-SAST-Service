"""Single local entrypoint for Agentic SAST Guardian."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


_CHILD_FLAG = "AGENTIC_SAST_STREAMLIT_CHILD"


def _is_streamlit_child(environ: dict[str, str] | None = None) -> bool:
    return (environ or os.environ).get(_CHILD_FLAG) == "1"


def _child_command() -> list[str]:
    return [sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve())]


def _launch_streamlit() -> int:
    environment = os.environ.copy()
    environment[_CHILD_FLAG] = "1"
    child = subprocess.Popen(_child_command(), env=environment)
    try:
        return child.wait()
    except KeyboardInterrupt:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        return 130


def main() -> int:
    if _is_streamlit_child():
        # Delayed import prevents Streamlit widgets during parent bootstrap/tests.
        load_dotenv(Path(__file__).with_name(".env"))
        from ui.app import render_app

        render_app()
        return 0
    return _launch_streamlit()


if __name__ == "__main__":
    raise SystemExit(main())
