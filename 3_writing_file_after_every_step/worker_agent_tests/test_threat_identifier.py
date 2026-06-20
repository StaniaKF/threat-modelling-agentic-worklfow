"""
Test script for the Threat Identifier agent in isolation.

Seeds threats.json with the initial state (empty threats array),
then calls the threat identifier with the mermaid diagram and business context.

Run from the project root:
    uv run python -m worker_agent_tests.test_threat_identifier
"""

import os
import json
import shutil
import asyncio
from contextlib import AsyncExitStack

from agents import Runner, RunConfig, OpenAIChatCompletionsModel, trace
from agents.tracing import set_trace_processors
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from utils.get_trace import FileSpanExporter
from worker_agents import initialise_threat_identification_tool, filesystem_params

env_path = os.path.join(os.path.dirname(__file__), "../.env")
load_dotenv(env_path)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

MODEL = "openai/gpt-4o-mini"
CLIENT = AsyncOpenAI(
    base_url=os.getenv("LITELLM_API_BASE_URL"),
    api_key=os.getenv("LITELLM_API_KEY"),
    timeout=300.0,
)


async def main() -> None:
    # Seed threats.json with initial fixture
    fixture_path = os.path.join(FIXTURES_DIR, "threats_initial.json")
    target_path = os.path.join(PROJECT_ROOT, "outputs", "threats.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy(fixture_path, target_path)
    print(f"Seeded threats.json from {fixture_path}")

    # Set up tracing
    set_trace_processors([FileSpanExporter("trace_test_threat_identifier.json")])

    async with AsyncExitStack() as stack:
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        tool = initialise_threat_identification_tool(mcp_servers=[filesystem_mcp_server])

        # Read input files to pass as context
        mermaid_path = os.path.join(PROJECT_ROOT, "inputs", "mermaid.md")
        context_path = os.path.join(PROJECT_ROOT, "inputs", "context.md")

        with open(mermaid_path, "r") as f:
            mermaid_content = f.read()
        with open(context_path, "r") as f:
            context_content = f.read()

        # Build the input message (same as what the coordinator would pass)
        input_message = (
            f"Today's date: 2026-06-15\n\n"
            f"Architecture diagram (mermaid):\n{mermaid_content}\n\n"
            f"Business context:\n{context_content}"
        )

        # Create a simple agent that just calls the tool
        from agents import Agent
        test_agent = Agent(
            name="Test Runner",
            instructions="Call the threat_identification tool with the provided input. Pass the entire message as the input.",
            tools=[tool],
            model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
        )

        with trace("Test: Threat Identifier"):
            result = Runner.run_streamed(
                test_agent,
                input_message,
                run_config=RunConfig(
                    model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
                ),
                max_turns=50,
            )
            async for event in result.stream_events():
                if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                    print(event.data.delta, end="", flush=True)
            print()

    # Print result summary
    with open(target_path, "r") as f:
        result_data = json.load(f)
    print(f"\n--- Result: {len(result_data.get('threats', []))} threats identified ---")
    for t in result_data.get("threats", [])[:3]:
        print(f"  [{t.get('stride_category')}] {t.get('element')}: {t.get('threat', '')[:80]}")
    if len(result_data.get("threats", [])) > 3:
        print(f"  ... and {len(result_data['threats']) - 3} more")


if __name__ == "__main__":
    asyncio.run(main())
