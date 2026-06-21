"""
Test script for the Mitigation Auditor agent in isolation.

Seeds threats.json with threats + risk + mitigations already filled,
then runs the auditor which queries AWS to check what's in place.

Run from the project root:
    uv run python -m worker_agent_tests.test_mitigation_auditor
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
from constants import FILESYSTEM_MCP_PARAMS, AWS_MCP_PARAMS, MODEL
from worker_agents.mitigation_auditor import INSTRUCTIONS

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
    fixture_path = os.path.join(FIXTURES_DIR, "threats_after_planner.json")
    target_path = os.path.join(PROJECT_ROOT, "outputs", "threats.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy(fixture_path, target_path)
    print(f"Seeded threats.json from {fixture_path}")

    set_trace_processors([FileSpanExporter("trace_test_mitigation_auditor.json")])

    async with AsyncExitStack() as stack:
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

        print("Warming up AWS MCP server...")
        aws_tools = await aws_mcp.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.")

        context_path = os.path.join(PROJECT_ROOT, "inputs", "context.md")
        cf_path = os.path.join(PROJECT_ROOT, "inputs", "cloud-formation.yaml")
        mermaid_path = os.path.join(PROJECT_ROOT, "inputs", "mermaid.md")

        with open(context_path) as f:
            context_content = f.read()
        cf_content = ""
        if os.path.exists(cf_path):
            with open(cf_path) as f:
                cf_content = f.read()
        with open(mermaid_path) as f:
            mermaid_content = f.read()

        input_message = (
            f"Business context:\n{context_content}\n\n"
            f"CloudFormation resource definitions:\n{cf_content}\n\n"
            f"Architecture diagram (mermaid):\n{mermaid_content}"
        )

        agent = Agent(
            name="Mitigation Auditor Agent",
            instructions=INSTRUCTIONS,
            model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
            mcp_servers=[filesystem_mcp, aws_mcp],
        )

        with trace("Test: Mitigation Auditor"):
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
    print(f"\n--- Result: {len(result_data.get('threats', []))} threats audited ---")
    for t in result_data.get("threats", []):
        in_place = t.get("mitigations_already_in_place", [])
        missing = t.get("mitigations_missing", [])
        in_count = len(in_place) if isinstance(in_place, list) else 0
        miss_count = len(missing) if isinstance(missing, list) else 0
        print(
            f"  [{t.get('stride_category')}] {t.get('element')}: {in_count} in place, {miss_count} missing, remaining_risk={t.get('remaining_risk')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
