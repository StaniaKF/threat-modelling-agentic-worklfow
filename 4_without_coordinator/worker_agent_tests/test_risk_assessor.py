"""
Test script for the Risk Assessor agent in isolation.

Seeds threats.json with threats already identified (no risk scores),
then runs the risk assessor with business context and CloudFormation.

Run from the project root:
    uv run python -m worker_agent_tests.test_risk_assessor
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
from worker_agents.risk_assessor import INSTRUCTIONS

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
    fixture_path = os.path.join(FIXTURES_DIR, "threats_after_identifier.json")
    target_path = os.path.join(PROJECT_ROOT, "outputs", "threats.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy(fixture_path, target_path)
    print(f"Seeded threats.json from {fixture_path}")

    set_trace_processors([FileSpanExporter("trace_test_risk_assessor.json")])

    async with AsyncExitStack() as stack:
        filesystem_mcp = await stack.enter_async_context(
            MCPServerStdio(FILESYSTEM_MCP_PARAMS)
        )

        context_path = os.path.join(PROJECT_ROOT, "inputs", "context.md")
        cf_path = os.path.join(PROJECT_ROOT, "inputs", "cloud-formation.yaml")

        with open(context_path) as f:
            context_content = f.read()
        cf_content = ""
        if os.path.exists(cf_path):
            with open(cf_path) as f:
                cf_content = f.read()

        input_message = (
            f"Business context:\n{context_content}\n\n"
            f"CloudFormation resource definitions:\n{cf_content}"
        )

        agent = Agent(
            name="Risk Assessor Agent",
            instructions=INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
            mcp_servers=[filesystem_mcp],
        )

        with trace("Test: Risk Assessor"):
            await Runner.run(
                agent,
                input_message,
                run_config=RunConfig(
                    model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
                ),
                max_turns=50,
            )

    with open(target_path) as f:
        result_data = json.load(f)
    print(f"\n--- Result: {len(result_data.get('threats', []))} threats assessed ---")
    for t in result_data.get("threats", []):
        print(
            f"  [{t.get('stride_category')}] {t.get('element')}: Impact={t.get('impact')} Likelihood={t.get('likelihood')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
