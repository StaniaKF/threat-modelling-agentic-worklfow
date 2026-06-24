"""
Test script for the Mitigation Auditor step in isolation.

Seeds threats.json with post-planner fixture, loops through each threat one at a time,
runs the auditor, and prints the structured result.

Run from the project root:
    uv run python -m workflow_agent_tests.test_mitigation_auditor
"""

import asyncio

from agents.mcp import MCPServerStdio

from constants import AWS_MCP_PARAMS
from workflow_agent_tests._common import (
    THREATS_JSON_PATH,
    print_threats_summary,
    read_input,
    setup,
)
from workflow_steps.mitigation_auditing import run_mitigation_audit


async def main() -> None:
    client, _ = setup(
        "threats_after_planner.json", "trace_test_mitigation_auditor.json"
    )

    cloudformation = read_input("cloud-formation.yaml")

    async with MCPServerStdio(
        params=AWS_MCP_PARAMS,
        client_session_timeout_seconds=300,
        tool_filter={"blocked_tool_names": ["aws___run_script"]},
    ) as aws_mcp:
        aws_tools = await aws_mcp.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.\n")

        await run_mitigation_audit(client, cloudformation, aws_mcp, THREATS_JSON_PATH)

    threats = print_threats_summary("Audit complete")
    for t in threats:
        in_place = len(t.get("mitigations_already_in_place") or [])
        missing = len(t.get("mitigations_missing") or [])
        print(
            f"  [{t.get('stride_category')}] {t.get('element')}: "
            f"{in_place} in place, {missing} missing, risk={t.get('remaining_risk')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
