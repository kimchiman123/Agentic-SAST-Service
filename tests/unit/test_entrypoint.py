import os
from unittest.mock import Mock, patch

import main


def test_parent_launches_exactly_one_streamlit_child() -> None:
    child = Mock()
    child.wait.return_value = 7
    with patch("main.subprocess.Popen", return_value=child) as popen:
        assert main.main() == 7
    command = popen.call_args.args[0]
    assert command[:3] == [main.sys.executable, "-m", "streamlit"]
    assert command[-1].endswith("main.py")
    assert popen.call_args.kwargs["env"]["AGENTIC_SAST_STREAMLIT_CHILD"] == "1"


def test_child_flag_prevents_recursive_subprocess() -> None:
    assert main._is_streamlit_child({"AGENTIC_SAST_STREAMLIT_CHILD": "1"})
    assert not main._is_streamlit_child({})


def test_interrupt_terminates_child() -> None:
    child = Mock()
    child.wait.side_effect = [KeyboardInterrupt(), None]
    with patch("main.subprocess.Popen", return_value=child):
        assert main._launch_streamlit() == 130
    child.terminate.assert_called_once()
