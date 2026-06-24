"""
Test script for the Mitigation Planner step in isolation.

Seeds threats.json with threats + risk scores, then runs the planner.

Run from the project root:
    uv run python -m workflow_agent_tests.test_mitigation_planner
"""

import asyncio

from agents.mcp import MCPServerStdio

from workflow_agent_tests._common import (
    THREATS_JSON_PATH,
    TEST_FILESYSTEM_MCP_PARAMS,
    print_threats_summary,
    setup,
)
from workflow_steps.mitigation_planning import plan_mitigations


async def main() -> None:
    client, run_config = setup(
        "threats_after_risk.json", "trace_test_mitigation_planner.json"
    )

    async with MCPServerStdio(TEST_FILESYSTEM_MCP_PARAMS) as filesystem_mcp:
        await plan_mitigations(client, run_config, filesystem_mcp, THREATS_JSON_PATH)

    threats = print_threats_summary("Threats with mitigations")
    for t in threats:
        count = len(t.get("all_possible_mitigations") or [])
        print(f"  [{t.get('stride_category')}] {t.get('element')}: {count} mitigations")


if __name__ == "__main__":
    asyncio.run(main())
