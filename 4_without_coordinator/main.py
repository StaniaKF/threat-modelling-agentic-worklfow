"""
Threat modelling CLI — runs the full workflow with validation.

Python orchestrates the pipeline directly (no LLM coordinator). Each agent is
called sequentially with programmatic validation + retry after each step.

- Validates each agent's output programmatically before proceeding to the next step

Requirements:
- An `inputs/` folder in the current directory with: context.md, mermaid.md, cloud-formation.yaml
- Environment variables set (or a .env file in the current directory):
  LITELLM_API_BASE_URL, LITELLM_API_KEY, AWS_PROFILE

Usage:
    uv run threat-model
    uv run python main.py
"""

import asyncio
from contextlib import AsyncExitStack

import typer
from agents import OpenAIChatCompletionsModel, RunConfig, add_trace_processor
from agents.mcp import MCPServerStdio

from constants import AWS_MCP_PARAMS, FILESYSTEM_MCP_PARAMS, MODEL
from tools import convert_to_csv_from_file
from utils.agent_factory import create_client
from utils.get_trace import FileSpanExporter
from utils.parsers import extract_service_name
from utils.setup_commands import (
    OUTPUTS_DIR,
    create_initial_threats_json,
    read_input,
    validate_environment,
    clean_outputs,
)
from workflow_steps.threat_identification import identify_threats
from workflow_steps.risk_assessment import assess_risks
from workflow_steps.mitigation_planning import plan_mitigations
from workflow_steps.mitigation_auditing import run_mitigation_audit

app = typer.Typer(
    name="threat-model",
    help="Automated threat modelling pipeline using STRIDE methodology.",
    add_completion=False,
)


async def run_workflow() -> None:
    """Execute the full threat modelling workflow pipeline."""
    client = create_client()
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client)
    )
    add_trace_processor(FileSpanExporter(str(OUTPUTS_DIR / "trace_output.json")))

    # Read System Specs
    context = read_input("context.md")
    diagram = read_input("mermaid.md")
    cloudformation = read_input("cloud-formation.yaml")

    service_project = extract_service_name(context)
    create_initial_threats_json(service_project)

    async with AsyncExitStack() as stack:
        # Initialize Core Runtime Protocol
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

        # Sequential Workflow Stages Execution
        await identify_threats(client, run_config, filesystem_mcp, diagram, context)
        await assess_risks(client, run_config, filesystem_mcp, context, cloudformation)
        await plan_mitigations(client, run_config, filesystem_mcp)
        await run_mitigation_audit(client, run_config, cloudformation, aws_mcp)

        # Output Consolidation Phase
        typer.echo("\n📊 Converting to CSV...")
        csv_result = convert_to_csv_from_file()
        typer.echo(f"   ✓ {csv_result}")

    typer.echo(f"\n✅ Done. Outputs written to: {OUTPUTS_DIR}")


@app.command()
def run() -> None:
    """Run the full threat modelling workflow with validation."""
    validate_environment()
    clean_outputs()
    asyncio.run(run_workflow())


if __name__ == "__main__":
    app()
