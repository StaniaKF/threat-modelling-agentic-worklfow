import json
from unittest.mock import MagicMock

import pytest
import typer

from constants import MAX_RETRIES
from utils.agent_run import (
    _build_agent_prompt,
    _get_current_threat_count,
    run_agent_with_validation,
)


# --- _get_current_threat_count ---


def test_get_current_threat_count_no_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "utils.agent_run.THREATS_JSON_PATH", tmp_path / "nonexistent.json"
    )
    assert _get_current_threat_count() == 0


def test_get_current_threat_count_invalid_json(monkeypatch, tmp_path):
    path = tmp_path / "threats.json"
    path.write_text("not json", encoding="utf-8")
    monkeypatch.setattr("utils.agent_run.THREATS_JSON_PATH", path)
    assert _get_current_threat_count() == 0


@pytest.mark.parametrize("count", [0, 1, 5, 10])
def test_get_current_threat_count_valid_file(monkeypatch, tmp_path, count):
    path = tmp_path / "threats.json"
    path.write_text(
        json.dumps({"threats": [{"id": i} for i in range(count)]}), encoding="utf-8"
    )
    monkeypatch.setattr("utils.agent_run.THREATS_JSON_PATH", path)
    assert _get_current_threat_count() == count


# --- _build_agent_prompt ---


def test_build_agent_prompt_first_attempt_returns_input():
    assert _build_agent_prompt("my input", 0, None) == "my input"


def test_build_agent_prompt_no_error_returns_input():
    assert _build_agent_prompt("my input", 2, None) == "my input"


def test_build_agent_prompt_retry_contains_original_and_error():
    result = _build_agent_prompt("my input", 1, "field X is missing")
    assert "my input" in result
    assert "field X is missing" in result
    assert "VALIDATION FAILED" in result


def test_build_agent_prompt_retry_shows_attempt_and_max_retries():
    result = _build_agent_prompt("base", 1, "some error")
    assert f"1/{MAX_RETRIES}" in result


@pytest.mark.parametrize(
    "attempt,error,expect_retry",
    [
        (0, "some error", False),
        (0, None, False),
        (1, None, False),
        (1, "error", True),
        (2, "error", True),
    ],
)
def test_build_agent_prompt_parametrized(attempt, error, expect_retry):
    result = _build_agent_prompt("base input", attempt, error)
    if expect_retry:
        assert "VALIDATION FAILED" in result
        assert "base input" in result
    else:
        assert result == "base input"


# --- run_agent_with_validation ---


class MockEvent:
    def __init__(self, event_type, data=None):
        self.type = event_type
        self.data = data


class MockDelta:
    def __init__(self, delta):
        self.delta = delta


class MockRunResult:
    def __init__(self, events=None):
        self._events = events or []

    async def stream_events(self):
        for event in self._events:
            yield event


@pytest.fixture(autouse=True)
def silence_printing(monkeypatch):
    monkeypatch.setattr("utils.agent_run.print_info", lambda *a, **kw: None)
    monkeypatch.setattr("utils.agent_run.print_success", lambda *a, **kw: None)
    monkeypatch.setattr("utils.agent_run.print_error", lambda *a, **kw: None)


@pytest.fixture(autouse=True)
def no_threats_file(monkeypatch, tmp_path):
    monkeypatch.setattr("utils.agent_run.THREATS_JSON_PATH", tmp_path / "threats.json")


@pytest.fixture
def mock_runner(monkeypatch):
    runner = MagicMock()
    runner.run_streamed.return_value = MockRunResult(events=[])
    monkeypatch.setattr("utils.agent_run.Runner", runner)
    return runner


async def test_run_agent_passes_on_first_attempt(mock_runner):
    validator = MagicMock(return_value=None)
    await run_agent_with_validation(
        MagicMock(), "input", validator, MagicMock(), "TestAgent"
    )
    assert mock_runner.run_streamed.call_count == 1
    assert validator.call_count == 1


async def test_run_agent_passes_on_retry(mock_runner):
    validator = MagicMock(side_effect=["validation error", None])
    await run_agent_with_validation(
        MagicMock(), "input", validator, MagicMock(), "TestAgent"
    )
    assert mock_runner.run_streamed.call_count == 2
    assert validator.call_count == 2


async def test_run_agent_all_attempts_fail_raises_exit(mock_runner):
    validator = MagicMock(return_value="always failing")
    with pytest.raises(typer.Exit) as exc:
        await run_agent_with_validation(
            MagicMock(), "input", validator, MagicMock(), "TestAgent"
        )
    assert exc.value.exit_code == 1
    assert mock_runner.run_streamed.call_count == 1 + MAX_RETRIES


async def test_run_agent_passes_correct_agent_to_runner(mock_runner):
    agent = MagicMock()
    run_config = MagicMock()
    validator = MagicMock(return_value=None)
    await run_agent_with_validation(agent, "hello", validator, run_config, "MyAgent")
    mock_runner.run_streamed.assert_called_once_with(
        agent, "hello", run_config=run_config, max_turns=50
    )


async def test_run_agent_streams_raw_response_event_to_stdout(monkeypatch, capsys):
    event = MockEvent("raw_response_event", MockDelta("streamed output"))
    runner = MagicMock()
    runner.run_streamed.return_value = MockRunResult(events=[event])
    monkeypatch.setattr("utils.agent_run.Runner", runner)
    validator = MagicMock(return_value=None)
    await run_agent_with_validation(
        MagicMock(), "input", validator, MagicMock(), "TestAgent"
    )
    assert "streamed output" in capsys.readouterr().out


async def test_run_agent_ignores_non_raw_response_events(monkeypatch, capsys):
    event = MockEvent("other_event_type")
    runner = MagicMock()
    runner.run_streamed.return_value = MockRunResult(events=[event])
    monkeypatch.setattr("utils.agent_run.Runner", runner)
    validator = MagicMock(return_value=None)
    await run_agent_with_validation(
        MagicMock(), "input", validator, MagicMock(), "TestAgent"
    )
    assert capsys.readouterr().out.strip() == ""


async def test_run_agent_retry_prompt_includes_validation_error(mock_runner):
    """On retry, the agent receives a prompt that includes the previous validation error."""
    calls = []

    def capture_call(agent, message, **kwargs):
        calls.append(message)
        return MockRunResult()

    mock_runner.run_streamed.side_effect = capture_call
    validator = MagicMock(side_effect=["first error", None])

    await run_agent_with_validation(
        MagicMock(), "original input", validator, MagicMock(), "TestAgent"
    )

    assert len(calls) == 2
    assert calls[0] == "original input"
    assert "first error" in calls[1]
