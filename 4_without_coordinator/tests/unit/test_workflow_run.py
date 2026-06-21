from unittest.mock import AsyncMock, MagicMock

import pytest

from constants import MODEL
from utils.workflow_run import (
    _create_agent,
    _create_client,
    _extract_service_name,
    run_workflow,
)


@pytest.mark.parametrize(
    "context,expected",
    [
        (
            "## Project / Service Name\nPayment API\n## Other Section\nstuff",
            "Payment API",
        ),
        (
            "# Project / Service Name\nAuth Service",
            "Auth Service",
        ),
        (
            "Project / Service Name\nMy App",
            "My App",
        ),
        (
            "No relevant header here",
            "Unknown Service",
        ),
        (
            "",
            "Unknown Service",
        ),
    ],
)
def test_extract_service_name(context, expected):
    assert _extract_service_name(context) == expected


def test_extract_service_name_skips_hash_headings_after_header():
    context = "## Project / Service Name\n# Still a heading\nActual Name"
    assert _extract_service_name(context) == "Actual Name"


def test_extract_service_name_skips_blank_lines_after_header():
    context = "## Project / Service Name\n\nPayment Service"
    assert _extract_service_name(context) == "Payment Service"


def test_extract_service_name_returns_first_non_empty_non_hash_line():
    context = "## Project / Service Name\n\n\nData Pipeline"
    assert _extract_service_name(context) == "Data Pipeline"


def test_extract_service_name_header_at_end_returns_unknown():
    context = "Some content\n## Project / Service Name"
    assert _extract_service_name(context) == "Unknown Service"


# --- _create_agent ---


def test_create_agent_builds_agent_with_correct_params(monkeypatch):
    mock_agent_cls = MagicMock()
    mock_model_cls = MagicMock()
    monkeypatch.setattr("utils.workflow_run.Agent", mock_agent_cls)
    monkeypatch.setattr("utils.workflow_run.OpenAIChatCompletionsModel", mock_model_cls)

    client = MagicMock()
    servers = [MagicMock()]
    _create_agent("MyAgent", "Do things", client, servers)

    mock_model_cls.assert_called_once_with(model=MODEL, openai_client=client)
    mock_agent_cls.assert_called_once_with(
        name="MyAgent",
        instructions="Do things",
        model=mock_model_cls.return_value,
        mcp_servers=servers,
    )


# --- _create_client ---


def test_create_client_passes_env_vars_to_openai(monkeypatch):
    monkeypatch.setenv("LITELLM_API_BASE_URL", "http://llm.example.com")
    monkeypatch.setenv("LITELLM_API_KEY", "test-key-123")
    mock_openai_cls = MagicMock()
    monkeypatch.setattr("utils.workflow_run.AsyncOpenAI", mock_openai_cls)

    _create_client()

    mock_openai_cls.assert_called_once_with(
        base_url="http://llm.example.com",
        api_key="test-key-123",
        timeout=300.0,
    )


# --- run_workflow ---


@pytest.fixture
def workflow_mocks(monkeypatch):
    """Patch all external dependencies for run_workflow."""
    monkeypatch.setattr("utils.workflow_run.OpenAIChatCompletionsModel", MagicMock())
    monkeypatch.setattr("utils.workflow_run.RunConfig", MagicMock())
    monkeypatch.setattr("utils.workflow_run.add_trace_processor", MagicMock())
    monkeypatch.setattr("utils.workflow_run.FileSpanExporter", MagicMock())
    monkeypatch.setattr("utils.workflow_run.Agent", MagicMock())
    monkeypatch.setattr("utils.workflow_run.trace", MagicMock())
    monkeypatch.setattr("utils.workflow_run.typer", MagicMock())
    monkeypatch.setattr(
        "utils.workflow_run._create_client", MagicMock(return_value=MagicMock())
    )
    monkeypatch.setattr(
        "utils.workflow_run.read_input",
        lambda name: {
            "context.md": "## Project / Service Name\nTest Service",
            "mermaid.md": "graph TD;",
            "cloud-formation.yaml": "",
        }.get(name, ""),
    )

    create_initial_mock = MagicMock()
    monkeypatch.setattr(
        "utils.workflow_run.create_initial_threats_json", create_initial_mock
    )

    filesystem_mock = AsyncMock()
    filesystem_mock.__aenter__ = AsyncMock(return_value=filesystem_mock)
    aws_mock = AsyncMock()
    aws_mock.__aenter__ = AsyncMock(return_value=aws_mock)
    aws_mock.list_tools = AsyncMock(return_value=[])
    monkeypatch.setattr(
        "utils.workflow_run.MCPServerStdio",
        MagicMock(side_effect=[filesystem_mock, aws_mock]),
    )

    run_agent_mock = AsyncMock()
    monkeypatch.setattr("utils.workflow_run.run_agent_with_validation", run_agent_mock)
    monkeypatch.setattr(
        "utils.workflow_run.convert_to_csv_from_file",
        MagicMock(return_value="3 threats"),
    )

    return {"create_initial": create_initial_mock, "run_agent": run_agent_mock}


async def test_run_workflow_calls_all_four_agents(workflow_mocks):
    await run_workflow()
    assert workflow_mocks["run_agent"].call_count == 4


async def test_run_workflow_extracts_and_passes_service_name(workflow_mocks):
    await run_workflow()
    workflow_mocks["create_initial"].assert_called_once_with("Test Service")


async def test_run_workflow_converts_to_csv_at_end(monkeypatch, workflow_mocks):
    csv_mock = MagicMock(return_value="done")
    monkeypatch.setattr("utils.workflow_run.convert_to_csv_from_file", csv_mock)
    await run_workflow()
    csv_mock.assert_called_once()
