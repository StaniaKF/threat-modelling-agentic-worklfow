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
    uv run threat-model (interactive prompt)
    uv run python main.py (interactive prompt)
    uv run python main.py --steps identify
    uv run python main.py --steps identify-assess-plan
    uv run python main.py --steps audit
"""

import asyncio
from contextlib import AsyncExitStack

import questionary
import typer
from agents import OpenAIChatCompletionsModel, RunConfig
from agents.mcp import MCPServerStdio
from agents.tracing import set_trace_processors

from constants import AWS_MCP_PARAMS, FILESYSTEM_MCP_PARAMS, MODEL
from utils.from_json_to_csv_converter import convert_to_csv_from_file
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
from validation.first_step_threats_json_validation import (
    WorkflowSteps,
    validate_threats_json_for_first_step,
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

TRACES_DIR = OUTPUTS_DIR / "traces"


async def run_workflow(steps: list[str]) -> None:
    """Execute the selected threat modelling workflow steps."""
    client = create_client()
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client)
    )

    context = read_input("context.md")
    diagram = read_input("mermaid.md")
    cloudformation = read_input("cloud-formation.yaml")

    if WorkflowSteps.IDENTIFY in steps:
        service_project = extract_service_name(context)
        create_initial_threats_json(service_project)

    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    validate_threats_json_for_first_step(steps[0])

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
        if WorkflowSteps.IDENTIFY in steps:
            set_trace_processors(
                [FileSpanExporter(str(TRACES_DIR / "trace_threat_identifier.json"))]
            )
            await identify_threats(client, run_config, filesystem_mcp, diagram, context)

        if WorkflowSteps.ASSESS in steps:
            set_trace_processors(
                [FileSpanExporter(str(TRACES_DIR / "trace_risk_assessor.json"))]
            )
            await assess_risks(
                client, run_config, filesystem_mcp, context, cloudformation
            )

        if WorkflowSteps.PLAN in steps:
            set_trace_processors(
                [FileSpanExporter(str(TRACES_DIR / "trace_mitigation_planner.json"))]
            )
            await plan_mitigations(client, run_config, filesystem_mcp)

        if WorkflowSteps.AUDIT in steps:
            set_trace_processors(
                [FileSpanExporter(str(TRACES_DIR / "trace_mitigation_auditor.json"))]
            )
            await run_mitigation_audit(client, cloudformation, aws_mcp)

        # Output Consolidation Phase
        typer.echo("\n📊 Converting to CSV...")
        csv_result = convert_to_csv_from_file()
        typer.echo(f"   ✓ {csv_result}")

    typer.echo(f"\n✅ Done. Outputs written to: {OUTPUTS_DIR}")


@app.command()
def run(
    steps: WorkflowSteps = typer.Option(
        None,
        "--steps",
        help="Select a valid sequential block of steps to run. "
        "Example: --steps identify-assess-plan",
    ),
) -> None:
    """Run the threat modelling workflow with validation."""
    if steps is None:
        raw_choice = questionary.select(
            "Select the workflow steps to run:",
            choices=[step.value for step in WorkflowSteps],
        ).ask()

        # When the user aborts the interactive prompt — pressing Ctrl+C or Ctrl+D during selection
        if raw_choice is None:
            raise typer.Exit(0)

        steps = WorkflowSteps(raw_choice)

    steps_to_run = steps.value.split("-")
    typer.echo(f"▶  Running steps: {', '.join(steps_to_run)}")
    validate_environment()
    if WorkflowSteps.IDENTIFY in steps_to_run:
        clean_outputs()
    asyncio.run(run_workflow(steps_to_run))


if __name__ == "__main__":
    app()
