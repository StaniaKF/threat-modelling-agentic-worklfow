"""
Test script for the Risk Assessor step in isolation.

Seeds threats.json with threats already identified (no risk scores),
then runs the risk assessor with business context and CloudFormation.

Run from the project root:
    uv run python -m workflow_agent_tests.test_risk_assessor
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
from workflow_steps.risk_assessment import assess_risks


async def main() -> None:
    client, run_config = setup(
        "threats_after_identifier.json", "trace_test_risk_assessor.json"
    )

    context = read_input("context.md")
    cloudformation = read_input("cloud-formation.yaml")

    async with MCPServerStdio(TEST_FILESYSTEM_MCP_PARAMS) as filesystem_mcp:
        await assess_risks(
            client,
            run_config,
            filesystem_mcp,
            context,
            cloudformation,
            THREATS_JSON_PATH,
        )

    threats = print_threats_summary("Threats assessed")
    for t in threats:
        print(
            f"  [{t.get('stride_category')}] {t.get('element')}: "
            f"Impact={t.get('impact')} Likelihood={t.get('likelihood')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
