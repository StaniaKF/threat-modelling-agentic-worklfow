"""
Test script for the Threat Identifier step in isolation.

Seeds threats.json with the initial state (empty threats array),
then runs the threat identifier directly with the mermaid diagram and business context.

Run from the project root:
    uv run python -m workflow_agent_tests.test_threat_identifier
"""

import asyncio

from agents.mcp import MCPServerStdio

from workflow_agent_tests._common import (
    THREATS_JSON_PATH,
    TEST_FILESYSTEM_MCP_PARAMS,
    print_threats_summary,
    read_input,
    setup,
)
from workflow_steps.threat_identification import identify_threats


async def main() -> None:
    client, run_config = setup(
        "threats_initial.json", "trace_test_threat_identifier.json"
    )

    diagram = read_input("mermaid.md")
    context = read_input("context.md")

    async with MCPServerStdio(TEST_FILESYSTEM_MCP_PARAMS) as filesystem_mcp:
        await identify_threats(
            client, run_config, filesystem_mcp, diagram, context, THREATS_JSON_PATH
        )

    threats = print_threats_summary("Threats identified")
    for t in threats[:5]:
        print(
            f"  [{t.get('stride_category')}] {t.get('element')}: {t.get('threat', '')[:80]}"
        )
    if len(threats) > 5:
        print(f"  ... and {len(threats) - 5} more")


if __name__ == "__main__":
    asyncio.run(main())
