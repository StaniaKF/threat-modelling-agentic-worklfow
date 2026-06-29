from unittest.mock import AsyncMock, MagicMock

import pytest

from constants import MODEL
from main import run_workflow
from utils.agent_factory import create_agent, create_client
from utils.parsers import extract_service_name

ALL_STEPS = ["Identify", "Assess", "Plan", "Audit"]


# --- extract_service_name ---


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
    assert extract_service_name(context) == expected


def test_extract_service_name_skips_hash_headings_after_header():
    context = "## Project / Service Name\n# Still a heading\nActual Name"
    assert extract_service_name(context) == "Actual Name"


def test_extract_service_name_skips_blank_lines_after_header():
    context = "## Project / Service Name\n\nPayment Service"
    assert extract_service_name(context) == "Payment Service"


def test_extract_service_name_returns_first_non_empty_non_hash_line():
    context = "## Project / Service Name\n\n\nData Pipeline"
    assert extract_service_name(context) == "Data Pipeline"


def test_extract_service_name_header_at_end_returns_unknown():
    context = "Some content\n## Project / Service Name"
    assert extract_service_name(context) == "Unknown Service"


# --- create_agent ---


def test_create_agent_builds_agent_with_correct_params(monkeypatch):
    mock_agent_cls = MagicMock()
    mock_model_cls = MagicMock()
    monkeypatch.setattr("utils.agent_factory.Agent", mock_agent_cls)
    monkeypatch.setattr(
        "utils.agent_factory.OpenAIChatCompletionsModel", mock_model_cls
    )

    client = MagicMock()
    servers = [MagicMock()]
    create_agent("MyAgent", "Do things", client, servers)

    mock_model_cls.assert_called_once_with(model=MODEL, openai_client=client)
    mock_agent_cls.assert_called_once_with(
        name="MyAgent",
        instructions="Do things",
        model=mock_model_cls.return_value,
        mcp_servers=servers,
    )


def test_create_agent_accepts_custom_model(monkeypatch):
    mock_agent_cls = MagicMock()
    mock_model_cls = MagicMock()
    monkeypatch.setattr("utils.agent_factory.Agent", mock_agent_cls)
    monkeypatch.setattr(
        "utils.agent_factory.OpenAIChatCompletionsModel", mock_model_cls
    )

    client = MagicMock()
    create_agent("Auditor", "Audit things", client, [], model="openai/gpt-4.1-mini")

    mock_model_cls.assert_called_once_with(
        model="openai/gpt-4.1-mini", openai_client=client
    )


# --- create_client ---


def test_create_client_passes_env_vars_to_openai(monkeypatch):
    monkeypatch.setenv("LITELLM_API_BASE_URL", "http://llm.example.com")
    monkeypatch.setenv("LITELLM_API_KEY", "test-key-123")
    mock_openai_cls = MagicMock()
    monkeypatch.setattr("utils.agent_factory.AsyncOpenAI", mock_openai_cls)

    create_client()

    mock_openai_cls.assert_called_once_with(
        base_url="http://llm.example.com",
        api_key="test-key-123",
        timeout=300.0,
    )


# --- run_workflow ---


@pytest.fixture
def workflow_mocks(monkeypatch):
    """Patch all external dependencies for run_workflow."""
    monkeypatch.setattr("main.OpenAIChatCompletionsModel", MagicMock())
    monkeypatch.setattr("main.RunConfig", MagicMock())
    monkeypatch.setattr("main.set_trace_processors", MagicMock())
    monkeypatch.setattr("main.FileSpanExporter", MagicMock())
    monkeypatch.setattr("main.TRACES_DIR", MagicMock())
    monkeypatch.setattr("main.print_info", lambda *a, **kw: None)
    monkeypatch.setattr("main.print_info_box", lambda *a, **kw: None)
    monkeypatch.setattr("main.print_success_box", lambda *a, **kw: None)
    monkeypatch.setattr("main.print_success", lambda *a, **kw: None)
    monkeypatch.setattr("main.create_client", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(
        "main.read_input",
        lambda name: {
            "context.md": "## Project / Service Name\nTest Service",
            "mermaid.md": "graph TD;",
            "cloud-formation.yaml": "",
        }.get(name, ""),
    )
    monkeypatch.setattr("main.validate_threats_json_for_first_step", MagicMock())

    create_initial_mock = MagicMock()
    monkeypatch.setattr("main.create_initial_threats_json", create_initial_mock)

    filesystem_mock = AsyncMock()
    filesystem_mock.__aenter__ = AsyncMock(return_value=filesystem_mock)
    aws_mock = AsyncMock()
    aws_mock.__aenter__ = AsyncMock(return_value=aws_mock)
    aws_mock.list_tools = AsyncMock(return_value=[])
    monkeypatch.setattr(
        "main.MCPServerStdio",
        MagicMock(side_effect=[filesystem_mock, aws_mock]),
    )

    identify_mock = AsyncMock()
    assess_mock = AsyncMock()
    plan_mock = AsyncMock()
    audit_mock = AsyncMock()
    monkeypatch.setattr("main.identify_threats", identify_mock)
    monkeypatch.setattr("main.assess_risks", assess_mock)
    monkeypatch.setattr("main.plan_mitigations", plan_mock)
    monkeypatch.setattr("main.run_mitigation_audit", audit_mock)

    monkeypatch.setattr(
        "main.convert_to_csv_from_file", MagicMock(return_value="3 threats")
    )

    return {
        "create_initial": create_initial_mock,
        "identify": identify_mock,
        "assess": assess_mock,
        "plan": plan_mock,
        "audit": audit_mock,
    }


async def test_run_workflow_calls_all_four_steps(workflow_mocks):
    await run_workflow(ALL_STEPS)
    workflow_mocks["identify"].assert_called_once()
    workflow_mocks["assess"].assert_called_once()
    workflow_mocks["plan"].assert_called_once()
    workflow_mocks["audit"].assert_called_once()


async def test_run_workflow_extracts_and_passes_service_name(workflow_mocks):
    await run_workflow(ALL_STEPS)
    workflow_mocks["create_initial"].assert_called_once_with("Test Service")


async def test_run_workflow_converts_to_csv_at_end(monkeypatch, workflow_mocks):
    csv_mock = MagicMock(return_value="done")
    monkeypatch.setattr("main.convert_to_csv_from_file", csv_mock)
    await run_workflow(ALL_STEPS)
    csv_mock.assert_called_once()


async def test_run_workflow_only_identify_skips_later_steps(workflow_mocks):
    await run_workflow(["Identify"])
    workflow_mocks["identify"].assert_called_once()
    workflow_mocks["assess"].assert_not_called()
    workflow_mocks["plan"].assert_not_called()
    workflow_mocks["audit"].assert_not_called()


async def test_run_workflow_only_assess_and_plan(workflow_mocks):
    await run_workflow(["Assess", "Plan"])
    workflow_mocks["identify"].assert_not_called()
    workflow_mocks["assess"].assert_called_once()
    workflow_mocks["plan"].assert_called_once()
    workflow_mocks["audit"].assert_not_called()


async def test_run_workflow_skips_create_initial_when_identify_not_selected(
    workflow_mocks,
):
    await run_workflow(["Assess"])
    workflow_mocks["create_initial"].assert_not_called()


async def test_run_workflow_only_audit(workflow_mocks):
    await run_workflow(["Audit"])
    workflow_mocks["identify"].assert_not_called()
    workflow_mocks["assess"].assert_not_called()
    workflow_mocks["plan"].assert_not_called()
    workflow_mocks["audit"].assert_called_once()
