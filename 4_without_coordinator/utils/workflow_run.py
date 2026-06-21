import os
from contextlib import AsyncExitStack

import typer
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    RunConfig,
    add_trace_processor,
    trace,
)
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI

from constants import MODEL, FILESYSTEM_MCP_PARAMS, AWS_MCP_PARAMS
from tools import convert_to_csv_from_file
from utils.agent_run import run_agent_with_validation
from utils.get_trace import FileSpanExporter
from utils.setup_commands import (
    OUTPUTS_DIR,
    read_input,
    create_initial_threats_json,
    TODAY,
)
from validation import (
    validate_after_threat_identifier,
    validate_after_risk_assessor,
    validate_after_mitigation_planner,
    validate_after_mitigation_auditor,
)
from worker_agents.mitigation_auditor import (
    INSTRUCTIONS as MITIGATION_AUDITOR_INSTRUCTIONS,
)
from worker_agents.mitigation_planner import (
    INSTRUCTIONS as MITIGATION_PLANNER_INSTRUCTIONS,
)
from worker_agents.risk_assessor import INSTRUCTIONS as RISK_ASSESSOR_INSTRUCTIONS
from worker_agents.threat_identifier import (
    INSTRUCTIONS as THREAT_IDENTIFIER_INSTRUCTIONS,
)


def _extract_service_name(context_text: str) -> str:
    """Safely extracts the service name under 'Project / Service Name' header."""
    lines = [line.strip() for line in context_text.splitlines()]
    for i, line in enumerate(lines):
        if "Project / Service Name" in line:
            for j in range(i + 1, len(lines)):
                if lines[j] and not lines[j].startswith("#"):
                    return lines[j]
    return "Unknown Service"


def _create_agent(
    name: str, instructions: str, client: AsyncOpenAI, mcp_servers: list
) -> Agent:
    """Helper factory to keep agent instantiation clean and uniform."""
    return Agent(
        name=name,
        instructions=instructions,
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client),
        mcp_servers=mcp_servers,
    )


def _create_client() -> AsyncOpenAI:
    """Create an AsyncOpenAI client with environment variables."""
    return AsyncOpenAI(
        base_url=os.getenv("LITELLM_API_BASE_URL"),
        api_key=os.getenv("LITELLM_API_KEY"),
        timeout=300.0,
    )


async def run_workflow() -> None:
    """Execute the full threat modelling workflow."""

    client = _create_client()
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client),
    )
    add_trace_processor(FileSpanExporter(str(OUTPUTS_DIR / "trace_output.json")))

    context = read_input("context.md")
    diagram = read_input("mermaid.md")
    cloudformation = read_input("cloud-formation.yaml")

    service_project = _extract_service_name(context)

    create_initial_threats_json(service_project)

    async with AsyncExitStack() as stack:
        # Start MCP servers
        filesystem_mcp = await stack.enter_async_context(
            MCPServerStdio(FILESYSTEM_MCP_PARAMS)
        )
        aws_mcp = await stack.enter_async_context(
            MCPServerStdio(
                params=AWS_MCP_PARAMS,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        aws_tools = await aws_mcp.list_tools()
        typer.echo(f"   ✓ AWS MCP ready ({len(aws_tools)} tools)")

        # --- Step 1: Threat Identification ---
        typer.echo("\n📋 Step 1/4: Threat Identification")

        threat_identifier_agent = _create_agent(
            "Threat Identifier Agent",
            THREAT_IDENTIFIER_INSTRUCTIONS,
            client,
            [filesystem_mcp],
        )
        threat_identifier_input = (
            f"Today's date: {TODAY}\n\n"
            f"Architecture diagram (mermaid):\n{diagram}\n\n"
            f"Business context:\n{context}"
        )

        with trace("Threat Identification"):
            await run_agent_with_validation(
                threat_identifier_agent,
                threat_identifier_input,
                validate_after_threat_identifier,
                run_config,
                "Threat Identifier",
            )

        # --- Step 2: Risk Assessment ---
        typer.echo("\n📊 Step 2/4: Risk Assessment")
        risk_assessor_agent = _create_agent(
            "Risk Assessor Agent", RISK_ASSESSOR_INSTRUCTIONS, client, [filesystem_mcp]
        )
        risk_input = (
            f"Business context:\n{context}\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}"
        )

        with trace("Risk Assessment"):
            await run_agent_with_validation(
                risk_assessor_agent,
                risk_input,
                validate_after_risk_assessor,
                run_config,
                "Risk Assessor",
            )

        # --- Step 3: Mitigation Planning ---
        typer.echo("\n🛡️ Step 3/4: Mitigation Planning")
        mitigation_planner = _create_agent(
            "Mitigation Planner Agent",
            MITIGATION_PLANNER_INSTRUCTIONS,
            client,
            [filesystem_mcp],
        )

        with trace("Mitigation Planning"):
            await run_agent_with_validation(
                mitigation_planner,
                "",
                validate_after_mitigation_planner,
                run_config,
                "Mitigation Planner",
            )

        # --- Step 4: Mitigation Audit ---
        typer.echo("\n🔍 Step 4/4: Mitigation Audit")
        mitigation_auditor_agent = _create_agent(
            "Mitigation Auditor Agent",
            MITIGATION_AUDITOR_INSTRUCTIONS,
            client,
            [filesystem_mcp, aws_mcp],
        )
        audit_input = (
            f"Business context:\n{context}\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}\n\n"
            f"Architecture diagram (mermaid):\n{diagram}"
        )

        with trace("Mitigation Audit"):
            await run_agent_with_validation(
                mitigation_auditor_agent,
                audit_input,
                validate_after_mitigation_auditor,
                run_config,
                "Mitigation Auditor",
            )

        # --- Step 5: Convert to CSV ---
        typer.echo("\n📊 Converting to CSV...")
        csv_result = convert_to_csv_from_file()
        typer.echo(f"   ✓ {csv_result}")

    typer.echo(f"\n✅ Done. Outputs written to: {OUTPUTS_DIR}")
