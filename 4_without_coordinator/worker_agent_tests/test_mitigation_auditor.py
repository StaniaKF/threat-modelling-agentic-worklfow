"""
Test script for the Mitigation Auditor agent in isolation (structured output, all threats).

Seeds threats.json with post-planner fixture, loops through each threat one at a time,
runs the auditor, and prints the structured result.

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
from constants import AWS_MCP_PARAMS
from worker_agents.mitigation_auditor import INSTRUCTIONS, ThreatAuditResult

env_path = os.path.join(os.path.dirname(__file__), "../.env")
load_dotenv(env_path)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

MODEL = "openai/gpt-4.1-mini"

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

    # Read CloudFormation for context
    cf_path = os.path.join(PROJECT_ROOT, "inputs", "cloud-formation.yaml")
    cf_content = ""
    if os.path.exists(cf_path):
        with open(cf_path) as f:
            cf_content = f.read()

    # Load threats
    with open(target_path) as f:
        data = json.load(f)
    threats = data["threats"]
    print(f"\nTotal threats to audit: {len(threats)}")

    async with AsyncExitStack() as stack:
        aws_mcp = await stack.enter_async_context(
            MCPServerStdio(
                params=AWS_MCP_PARAMS,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        print("Warming up AWS MCP server...")
        aws_tools = await aws_mcp.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.\n")

        for i, threat in enumerate(threats):
            print(
                f"--- Threat {i + 1}/{len(threats)}: [{threat['stride_category']}] {threat['element']} ---"
            )

            input_message = (
                f"Assess this threat:\n"
                f"{json.dumps(threat, indent=2)}\n\n"
                f"AWS Account ID: 869935085421, Region: eu-west-1\n\n"
                f"CloudFormation resource definitions:\n{cf_content}\n\n"
                f"Use the AWS MCP to query live infrastructure for the '{threat.get('element', '')}' component. "
                f"Use FILTERED queries with specific resource IDs. "
                f"If an AWS call fails, use the CloudFormation config above as evidence.\n\n"
                f"IMPORTANT: Keep your AWS queries minimal and targeted. "
                f"Make at most 5-6 AWS calls total."
            )

            agent = Agent(
                name="Mitigation Auditor Agent",
                instructions=INSTRUCTIONS,
                model=OpenAIChatCompletionsModel(model=MODEL, openai_client=CLIENT),
                mcp_servers=[aws_mcp],
                output_type=ThreatAuditResult,
            )

            try:
                with trace(f"Test: Mitigation Auditor - Threat {i}"):
                    result = await Runner.run(
                        agent,
                        input_message,
                        run_config=RunConfig(
                            model=OpenAIChatCompletionsModel(
                                model=MODEL, openai_client=CLIENT
                            ),
                        ),
                        max_turns=50,
                    )

                audit_result = result.final_output_as(ThreatAuditResult)
                if audit_result:
                    in_place = [
                        a
                        for a in audit_result.mitigations_assessment
                        if a.status == "already_in_place"
                    ]
                    missing = [
                        a
                        for a in audit_result.mitigations_assessment
                        if a.status == "missing"
                    ]
                    print(
                        f"  ✓ {len(in_place)} in place, {len(missing)} missing, remaining_risk={audit_result.remaining_risk}"
                    )

                    # Update the threat in data and write to outputs/threats.json
                    all_mits = threat.get("all_possible_mitigations", [])
                    in_place_list = []
                    missing_list = []
                    for a in audit_result.mitigations_assessment:
                        name = (
                            f"{a.mitigation_name} ({a.note})"
                            if a.note
                            else a.mitigation_name
                        )
                        if a.status == "already_in_place":
                            in_place_list.append(name)
                        else:
                            missing_list.append(name)

                    # Auto-add unassessed mitigations to missing
                    assessed_names = {
                        a.mitigation_name for a in audit_result.mitigations_assessment
                    }
                    for m in all_mits:
                        if m not in assessed_names:
                            missing_list.append(m)

                    threats[i]["mitigations_already_in_place"] = in_place_list
                    threats[i]["mitigations_missing"] = missing_list
                    threats[i]["ai_proposed_mitigations"] = (
                        audit_result.ai_proposed_mitigations
                    )
                    threats[i]["remaining_risk"] = audit_result.remaining_risk
                else:
                    print("  ✗ No structured output returned")
            except Exception as e:
                print(f"  ✗ Error: {type(e).__name__}: {str(e)[:100]}")

            print()

    # Write final results to outputs/threats.json
    data["threats"] = threats
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n=== Done — results written to {target_path} ===")


if __name__ == "__main__":
    asyncio.run(main())
