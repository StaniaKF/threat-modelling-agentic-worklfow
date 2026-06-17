"""
Threat modelling workflow with programmatic validation after each agent step.

After each agent writes outputs/threats.json, a Python validator checks the output.
If validation fails, the agent is re-invoked with the error details (up to 2 retries
per step).

Key differences from main.py:
- Validates each agent's output programmatically before proceeding to the next step

Run from the project root:
    uv run python main_with_validation.py
"""

import os
import shutil
import asyncio
from contextlib import AsyncExitStack
from pathlib import Path

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

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)

MODEL = "openai/gpt-4o-mini"

CLIENT = AsyncOpenAI(
    base_url=os.getenv("LITELLM_API_BASE_URL"),
    api_key=os.getenv("LITELLM_API_KEY"),
    timeout=300.0,
)

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUTS_DIR = PROJECT_ROOT / "outputs"


def clean_outputs() -> None:
    """Remove all output files from the outputs/ directory before a fresh run."""
    if OUTPUTS_DIR.exists():
        shutil.rmtree(OUTPUTS_DIR)
    OUTPUTS_DIR.mkdir(exist_ok=True)
    print(f"Cleaned outputs directory: {OUTPUTS_DIR}")


def run_config() -> RunConfig:
    return RunConfig(
        model=OpenAIChatCompletionsModel(
            model=MODEL,
            openai_client=CLIENT,
        )
    )


async def main() -> None:
    # Clean previous outputs
    clean_outputs()

    # Add local trace exporter — writes to outputs/ folder
    trace_output_path = str(OUTPUTS_DIR / "trace_output_with_validation.json")
    add_trace_processor(FileSpanExporter(trace_output_path))

    async with AsyncExitStack() as stack:
        # Filesystem server - shared by coordinator and all workers
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        # AWS MCP server - used by the mitigation auditor
        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(
                params=aws_mcp_params,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        # Warm up AWS MCP server to avoid cold-start delays
        print("Warming up AWS MCP server...")
        aws_tools = await aws_mcp_server.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.")

        # Worker agents with validation — all get filesystem MCP access
        threat_modelling_tool = initialise_threat_identification_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )
        risk_assessor_tool = initialise_risk_assessor_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )
        mitigation_planner_tool = initialise_mitigation_planner_tool_with_validation(
            mcp_servers=[filesystem_mcp_server]
        )

        # Mitigation auditor gets BOTH filesystem and AWS MCP servers
        mitigation_auditor_tool = initialise_mitigation_auditor_tool_with_validation(
            mcp_servers=[filesystem_mcp_server, aws_mcp_server]
        )

        # Coordinator gets filesystem access + all worker tools + convert_to_csv
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

        with trace("Threat modelling workflow (with validation)"):
            result = Runner.run_streamed(
                coordinator_agent,
                "Run the full threat identification and risk assessment workflow.",
                run_config=run_config(),
                max_turns=50,
            )
            async for event in result.stream_events():
                if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                    print(event.data.delta, end="", flush=True)
            print()  # Final newline


if __name__ == "__main__":
    asyncio.run(main())
