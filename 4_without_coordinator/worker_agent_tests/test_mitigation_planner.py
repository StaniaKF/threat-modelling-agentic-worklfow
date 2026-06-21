"""
Test script for the Mitigation Planner agent in isolation.

Seeds threats.json with threats + risk scores, then runs the planner.

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
from constants import FILESYSTEM_MCP_PARAMS, MODEL
from worker_agents.mitigation_planner import INSTRUCTIONS

env_path = os.path.join(os.path.dirname(__file__), "../.env")
load_dotenv(env_path)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

CLIENT = AsyncOpenAI(
    base_url=os.getenv("LITELLM_API_BASE_URL"),
    api_key=os.getenv("LITELLM_API_KEY"),
    timeout=300.0,
)


async def main() -> None:
    fixture_path = os.path.join(FIXTURES_DIR, "threats_after_risk.json")
    target_path = os.path.join(PROJECT_ROOT, "outputs", "threats.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy(fixture_path, target_path)
    print(f"Seeded threats.json from {fixture_path}")

    set_trace_processors([FileSpanExporter("trace_test_mitigation_planner.json")])

    async with AsyncExitStack() as stack:
        filesystem_mcp = await stack.enter_async_context(
            MCPServerStdio(FILESYSTEM_MCP_PARAMS)
        )

        agent = Agent(
            name="Mitigation Planner Agent",
            instructions=INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
            mcp_servers=[filesystem_mcp],
        )

        with trace("Test: Mitigation Planner"):
            await Runner.run(
                agent,
                "",
                run_config=RunConfig(
                    model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
                ),
                max_turns=50,
            )

    with open(target_path) as f:
        result_data = json.load(f)
    print(
        f"\n--- Result: {len(result_data.get('threats', []))} threats with mitigations ---"
    )
    for t in result_data.get("threats", []):
        mits = t.get("all_possible_mitigations", [])
        count = len(mits) if isinstance(mits, list) else 0
        print(f"  [{t.get('stride_category')}] {t.get('element')}: {count} mitigations")


if __name__ == "__main__":
    asyncio.run(main())
