"""Opt-in live validation; never run in the default test suite."""

import os
import tempfile
from pathlib import Path

import pytest
from dotenv import load_dotenv

from core.agent import AnalysisLimits, OpenAIAgent
from core.batch_analysis import execute_two_passes, pack_contexts
from core.config import RuntimeSettings


pytestmark = pytest.mark.live_nvidia


@pytest.mark.skipif(os.environ.get("RUN_LIVE_NVIDIA") != "1", reason="set RUN_LIVE_NVIDIA=1 to permit real NVIDIA calls")
def test_two_contexts_round_trip_through_nvidia_without_secret_output() -> None:
    # Keep project secrets out of the normal test-collection process.  This
    # file is only executed after the explicit RUN_LIVE_NVIDIA opt-in above.
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    settings = RuntimeSettings.from_env()
    if settings.provider != "nvidia" or not settings.api_key:
        pytest.skip("NVIDIA_API_KEY is not configured")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "app.py"
        source.write_text("def handler(value):\n    return value\n", encoding="utf-8")
        contexts = [
            {"file_path": "app.py", "start_line": 1, "code_snippet": "def handler(value):"},
            {"file_path": "app.py", "start_line": 2, "code_snippet": "return value"},
        ]
        batches = pack_contexts(contexts, limits=settings.batch)
        assert len(batches) == 1
        agent = OpenAIAgent(
            target_root=str(root), api_key=settings.api_key, model=settings.model,
            limits=AnalysisLimits(max_llm_calls=2), context_window_tokens=settings.nvidia_context_window_tokens,
        )
        analyses, verifications = execute_two_passes(batches, agent.run_batch_pass, request_budget=2)
    assert analyses[0].request_count == 1
    assert verifications[0].request_count == 1
    assert analyses[0].status == "completed"
    assert verifications[0].status == "completed"
