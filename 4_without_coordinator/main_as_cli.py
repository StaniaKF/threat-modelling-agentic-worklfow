"""
Threat modelling CLI — runs the full workflow with validation from any directory.

Requirements:
- An `inputs/` folder in the current directory with: context.md, mermaid.md, cloud-formation.yaml
- Environment variables set (or a .env file in the current directory):
  LITELLM_API_BASE_URL, LITELLM_API_KEY, AWS_PROFILE

Usage:
    uv run python main_as_cli.py
"""

import os
import shutil
import asyncio
from pathlib import Path
from contextlib import AsyncExitStack

import typer
from agents import Runner, RunConfig, OpenAIChatCompletionsModel, trace
from agents.tracing import add_trace_processor
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from utils.get_trace import FileSpanExporter
from tools import convert_to_csv
from coordinator_agent import initialise_coordinator_agent
from worker_agents import (
    initialise_threat_identification_tool_with_validation,
    initialise_risk_assessor_tool_with_validation,
    initialise_mitigation_planner_tool_with_validation,
    initialise_mitigation_auditor_tool_with_validation,
    filesystem_params,
    aws_mcp_params,
)

app = typer.Typer(
    name="threat-model",
    help="Automated threat modelling pipeline using STRIDE methodology.",
    add_completion=False,
)

MODEL = "openai/gpt-4o-mini"

REQUIRED_ENV_VARS = ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]


def _validate_environment() -> None:
    """Check that required environment variables and input files are present."""
    # Load .env from CWD if it exists (does not override existing env vars)
    load_dotenv(Path.cwd() / ".env")

    missing_vars = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
    if missing_vars:
        typer.echo(
            f"❌ Missing required environment variables: {', '.join(missing_vars)}\n"
            f"Set them in your shell or provide a .env file in the current directory.",
            err=True,
        )
        raise typer.Exit(1)

    inputs_dir = Path.cwd() / "inputs"
    if not inputs_dir.exists():
        typer.echo(
            f"❌ inputs/ directory not found in {Path.cwd()}\n"
            f"Create it with at least mermaid.md inside.",
            err=True,
        )
        raise typer.Exit(1)

    mermaid_path = inputs_dir / "mermaid.md"
    if not mermaid_path.exists():
        typer.echo(
            "❌ inputs/mermaid.md not found. This file is required (architecture diagram).",
            err=True,
        )
        raise typer.Exit(1)


def _clean_outputs() -> Path:
    """Remove and recreate the outputs/ directory. Returns the path."""
    outputs_dir = Path.cwd() / "outputs"
    if outputs_dir.exists():
        shutil.rmtree(outputs_dir)
    outputs_dir.mkdir(exist_ok=True)
    typer.echo(f"📁 Cleaned outputs directory: {outputs_dir}")
    return outputs_dir


async def _run_workflow(outputs_dir: Path) -> None:
    """Execute the full threat modelling workflow with validation."""
    client = AsyncOpenAI(
        base_url=os.getenv("LITELLM_API_BASE_URL"),
        api_key=os.getenv("LITELLM_API_KEY"),
        timeout=300.0,
    )

    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client),
    )

    trace_path = str(outputs_dir / "trace_output.json")
    add_trace_processor(FileSpanExporter(trace_path))

    async with AsyncExitStack() as stack:
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(
                params=aws_mcp_params,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        typer.echo("🔌 Warming up AWS MCP server...")
        aws_tools = await aws_mcp_server.list_tools()
        typer.echo(f"✓ AWS MCP server ready. {len(aws_tools)} tools available.")

        # Worker agents with validation
        threat_modelling_tool = initialise_threat_identification_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )
        risk_assessor_tool = initialise_risk_assessor_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )
        mitigation_planner_tool = initialise_mitigation_planner_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )
        mitigation_auditor_tool = initialise_mitigation_auditor_tool_with_validation(
            mcp_servers=[filesystem_mcp_server, aws_mcp_server]
        )

        coordinator_tools = [
            threat_modelling_tool,
            risk_assessor_tool,
            mitigation_planner_tool,
            mitigation_auditor_tool,
            convert_to_csv,
        ]
        coordinator_agent = initialise_coordinator_agent(
            mcp_servers=[filesystem_mcp_server],
            tools=coordinator_tools,
        )

        typer.echo("🚀 Starting threat modelling workflow...\n")

        with trace("Threat modelling workflow (CLI)"):
            result = Runner.run_streamed(
                coordinator_agent,
                "Run the full threat identification and risk assessment workflow.",
                run_config=run_config,
                max_turns=50,
            )
            async for event in result.stream_events():
                if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                    print(event.data.delta, end="", flush=True)
            print()

    typer.echo(f"\n✅ Done. Outputs written to: {outputs_dir}")


@app.command()
def run() -> None:
    """Run the full threat modelling workflow with validation."""
    _validate_environment()
    outputs_dir = _clean_outputs()
    asyncio.run(_run_workflow(outputs_dir))


if __name__ == "__main__":
    app()
