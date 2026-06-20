"""
Test script for the Mitigation Planner agent in isolation.

Seeds threats.json with threats + risk scores already filled,
then calls the mitigation planner.

Run from the project root:
    uv run python -m worker_agent_tests.test_mitigation_planner
"""

import os
import json
import shutil
import asyncio
from contextlib import AsyncExitStack

from agents import Agent, Runner, RunConfig, OpenAIChatCompletionsModel, trace
from agents.tracing import set_trace_processors
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from utils.get_trace import FileSpanExporter
from worker_agents import initialise_mitigation_planner_tool, filesystem_params

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
    # Seed threats.json with post-risk fixture
    fixture_path = os.path.join(FIXTURES_DIR, "threats_after_risk.json")
    target_path = os.path.join(PROJECT_ROOT, "outputs", "threats.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy(fixture_path, target_path)
    print(f"Seeded threats.json from {fixture_path}")

    set_trace_processors([FileSpanExporter("trace_test_mitigation_planner.json")])

    async with AsyncExitStack() as stack:
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        tool = initialise_mitigation_planner_tool(mcp_servers=[filesystem_mcp_server])

        # Planner needs no additional input — it reads threats.json directly
        input_message = "Identify all possible mitigations for the threats in threats.json."

        test_agent = Agent(
            name="Test Runner",
            instructions="Call the mitigation_planning tool with the provided input. Pass the entire message as the input.",
            tools=[tool],
            model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
        )

        with trace("Test: Mitigation Planner"):
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
    print(f"\n--- Result: {len(result_data.get('threats', []))} threats with mitigations ---")
    for t in result_data.get("threats", []):
        mitigations = t.get("all_possible_mitigations", [])
        count = len(mitigations) if isinstance(mitigations, list) else 0
        print(f"  [{t.get('stride_category')}] {t.get('element')}: {count} mitigations proposed")


if __name__ == "__main__":
    asyncio.run(main())
