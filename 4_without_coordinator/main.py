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

import json
import os
import shutil
import asyncio
from datetime import date
from pathlib import Path
from contextlib import AsyncExitStack

import typer
from agents import Agent, Runner, RunConfig, OpenAIChatCompletionsModel, trace
from agents.tracing import add_trace_processor
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from utils.get_trace import FileSpanExporter
from tools.convert_to_csv import convert_to_csv_from_file
from validation import (
    validate_after_threat_identifier,
    validate_after_risk_assessor,
    validate_after_mitigation_planner,
    validate_after_mitigation_auditor,
)
from worker_agents.common import filesystem_params, aws_mcp_params, WORKER_MODEL
from worker_agents.threat_identifier import (
    INSTRUCTIONS as THREAT_IDENTIFIER_INSTRUCTIONS,
)
from worker_agents.risk_assessor import INSTRUCTIONS as RISK_ASSESSOR_INSTRUCTIONS
from worker_agents.mitigation_planner import (
    INSTRUCTIONS as MITIGATION_PLANNER_INSTRUCTIONS,
)
from worker_agents.mitigation_auditor import (
    INSTRUCTIONS as MITIGATION_AUDITOR_INSTRUCTIONS,
)

app = typer.Typer(
    name="threat-model",
    help="Automated threat modelling pipeline using STRIDE methodology.",
    add_completion=False,
)

TODAY = date.today().isoformat()
OUTPUTS_DIR = Path.cwd() / "outputs"
INPUTS_DIR = Path.cwd() / "inputs"
THREATS_JSON_PATH = OUTPUTS_DIR / "threats.json"

REQUIRED_ENV_VARS = ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]
MAX_RETRIES = 2


def _validate_environment() -> None:
    """Check that required environment variables and input files are present."""
    load_dotenv(Path.cwd() / ".env")

    missing_vars = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
    if missing_vars:
        typer.echo(
            f"❌ Missing required environment variables: {', '.join(missing_vars)}\n"
            f"Set them in your shell or provide a .env file in the current directory.",
            err=True,
        )
        raise typer.Exit(1)

    if not INPUTS_DIR.exists():
        typer.echo(f"❌ inputs/ directory not found in {Path.cwd()}", err=True)
        raise typer.Exit(1)

    if not (INPUTS_DIR / "mermaid.md").exists():
        typer.echo("❌ inputs/mermaid.md not found. This file is required.", err=True)
        raise typer.Exit(1)


def _clean_outputs() -> None:
    """Remove and recreate the outputs/ directory."""
    if OUTPUTS_DIR.exists():
        shutil.rmtree(OUTPUTS_DIR)
    OUTPUTS_DIR.mkdir(exist_ok=True)
    typer.echo(f"📁 Cleaned outputs directory: {OUTPUTS_DIR}")


def _read_input(filename: str) -> str:
    """Read an input file, returning empty string if it doesn't exist."""
    path = INPUTS_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _create_initial_threats_json(service_project: str) -> None:
    """Create the initial threats.json with metadata."""
    data = {
        "metadata": {
            "date_of_analysis": TODAY,
            "service_project": service_project,
        },
        "threats": [],
    }
    THREATS_JSON_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"📄 Created initial outputs/threats.json (service: {service_project})")


async def _run_agent_with_validation(
    agent: Agent,
    input_message: str,
    validator,
    run_config: RunConfig,
    agent_name: str,
) -> None:
    """Run an agent (streamed) with validation and retry logic.

    Streams the agent's output to stdout in real-time, then validates
    the resulting threats.json. Retries on validation failure.
    """
    # Snapshot threat count before
    pre_threat_count = 0
    if THREATS_JSON_PATH.exists():
        try:
            pre_data = json.loads(THREATS_JSON_PATH.read_text(encoding="utf-8"))
            pre_threat_count = len(pre_data.get("threats", []))
        except (json.JSONDecodeError, KeyError):
            pass

    validation_error: str | None = None

    for attempt in range(1 + MAX_RETRIES):
        if attempt == 0:
            message = input_message
        else:
            message = (
                f"{input_message}\n\n"
                f"⚠️ VALIDATION FAILED (attempt {attempt}/{MAX_RETRIES}). "
                f"Your previous output did not pass validation.\n"
                f"Errors:\n{validation_error}\n\n"
                f"Please re-read outputs/threats.json and fix these specific issues."
            )

        typer.echo(f"  🔄 Running {agent_name} (attempt {attempt + 1})...")

        # Stream the agent's output
        result = Runner.run_streamed(
            agent, message, run_config=run_config, max_turns=50
        )
        async for event in result.stream_events():
            if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                print(event.data.delta, end="", flush=True)
        print()  # Newline after stream ends

        # Validate after the agent has fully completed
        validation_error = validator(pre_threat_count)

        if validation_error is None:
            typer.echo(f"  ✓ {agent_name} — validation passed")
            return

        typer.echo(f"  ✗ {agent_name} — validation failed: {validation_error[:150]}")

    typer.echo(f"❌ {agent_name} FAILED after {1 + MAX_RETRIES} attempts.", err=True)
    typer.echo(f"   Last errors: {validation_error}", err=True)
    raise typer.Exit(1)


async def _run_workflow() -> None:
    """Execute the full threat modelling workflow."""
    client = AsyncOpenAI(
        base_url=os.getenv("LITELLM_API_BASE_URL"),
        api_key=os.getenv("LITELLM_API_KEY"),
        timeout=300.0,
    )
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=client),
    )

    add_trace_processor(FileSpanExporter(str(OUTPUTS_DIR / "trace_output.json")))

    # Read inputs
    context = _read_input("context.md")
    diagram = _read_input("mermaid.md")
    cloudformation = _read_input("cloud-formation.yaml")

    # Extract service name from context
    service_project = "Unknown Service"
    lines = context.splitlines()
    for i, line in enumerate(lines):
        if "Project / Service Name" in line:
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    service_project = lines[j].strip()
                    break
            break

    # Create initial threats.json
    _create_initial_threats_json(service_project)

    async with AsyncExitStack() as stack:
        # Start MCP servers
        filesystem_mcp = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        aws_mcp = await stack.enter_async_context(
            MCPServerStdio(
                params=aws_mcp_params,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        typer.echo("🔌 Warming up AWS MCP server...")
        aws_tools = await aws_mcp.list_tools()
        typer.echo(f"   ✓ AWS MCP ready ({len(aws_tools)} tools)")

        # --- Step 1: Threat Identification ---
        typer.echo("\n📋 Step 1/4: Threat Identification")
        threat_identifier = Agent(
            name="Threat Identifier Agent",
            instructions=THREAT_IDENTIFIER_INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=client),
            mcp_servers=[filesystem_mcp],
        )
        threat_input = (
            f"Today's date: {TODAY}\n\n"
            f"Architecture diagram (mermaid):\n{diagram}\n\n"
            f"Business context:\n{context}"
        )

        def threat_validator(_count: int) -> str | None:
            return validate_after_threat_identifier()

        with trace("Threat Identification"):
            await _run_agent_with_validation(
                threat_identifier,
                threat_input,
                threat_validator,
                run_config,
                "Threat Identifier",
            )

        # --- Step 2: Risk Assessment ---
        typer.echo("\n📊 Step 2/4: Risk Assessment")
        risk_assessor = Agent(
            name="Risk Assessor Agent",
            instructions=RISK_ASSESSOR_INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=client),
            mcp_servers=[filesystem_mcp],
        )
        risk_input = (
            f"Business context:\n{context}\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}"
        )

        with trace("Risk Assessment"):
            await _run_agent_with_validation(
                risk_assessor,
                risk_input,
                validate_after_risk_assessor,
                run_config,
                "Risk Assessor",
            )

        # --- Step 3: Mitigation Planning ---
        typer.echo("\n🛡️ Step 3/4: Mitigation Planning")
        mitigation_planner = Agent(
            name="Mitigation Planner Agent",
            instructions=MITIGATION_PLANNER_INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=client),
            mcp_servers=[filesystem_mcp],
        )

        with trace("Mitigation Planning"):
            await _run_agent_with_validation(
                mitigation_planner,
                "",
                validate_after_mitigation_planner,
                run_config,
                "Mitigation Planner",
            )

        # --- Step 4: Mitigation Audit ---
        typer.echo("\n🔍 Step 4/4: Mitigation Audit")
        mitigation_auditor = Agent(
            name="Mitigation Auditor Agent",
            instructions=MITIGATION_AUDITOR_INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=client),
            mcp_servers=[filesystem_mcp, aws_mcp],
        )
        audit_input = (
            f"Business context:\n{context}\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}\n\n"
            f"Architecture diagram (mermaid):\n{diagram}"
        )

        with trace("Mitigation Audit"):
            await _run_agent_with_validation(
                mitigation_auditor,
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


@app.command()
def run() -> None:
    """Run the full threat modelling workflow with validation."""
    _validate_environment()
    _clean_outputs()
    asyncio.run(_run_workflow())


if __name__ == "__main__":
    app()
