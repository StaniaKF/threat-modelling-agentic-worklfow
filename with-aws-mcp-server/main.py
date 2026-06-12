import os
import asyncio
from contextlib import AsyncExitStack

from agents import Agent, OpenAIChatCompletionsModel, Runner, RunConfig, trace
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from worker_agents import (
    initialise_threat_identification_tool,
    initialise_risk_assessor_tool,
    initialise_mitigation_planner_tool,
    initialise_mitigation_auditor_tool,
    filesystem_params,
    threat_modelling_params,
    aws_mcp_params,
)

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)

MODEL = "openai/gpt-4o-mini"

CLIENT = AsyncOpenAI(
    base_url=os.getenv("LITELLM_API_BASE_URL"),
    api_key=os.getenv("LITELLM_API_KEY"),
    timeout=300.0,
)


def run_config() -> RunConfig:
    return RunConfig(
        model=OpenAIChatCompletionsModel(
            model=MODEL,
            openai_client=CLIENT,
        )
    )


COORDINATOR_INSTRUCTIONS = """
    You are a threat modelling coordinator. Your job is to orchestrate specialist agents to produce a comprehensive threat model.

    You have access to these tools:
    - threat_identification: Identifies threats in the architecture using STRIDE methodology
    - risk_assessment: Assesses impact, likelihood, and risk level for identified threats
    - mitigation_planning: Identifies all possible mitigations and proposes high-risk missing mitigations
    - mitigation_audit: Checks which mitigations are already in place and which are missing

    All tools are self-contained - they have their own access to the architecture diagram and threat model data.
    You do NOT need to provide them with any file content or diagrams. Just call them.

    Workflow - execute in this exact order:
    1. Call threat_identification. No input needed - it reads the diagram itself.
    2. Call risk_assessment, passing it the output from step 1.
    3. Call mitigation_planning, passing it the output from steps 1 and 2.
    4. Call mitigation_audit, passing it the output from steps 1, 2, and 3.
    5. Present the combined results clearly.

    Rules:
    - Execute tools in the exact order above. Each depends on the previous outputs.
    - Do not perform any analysis yourself - only use the tools.
    - Do not ask the user for any input - everything is already available to the tools.
    - Do not modify the tools' output.
    - The final output should cover: STRIDE Category, Element, Threat, Attack Method, Impact, Likelihood, Risk, All Possible Mitigations, Mitigations In Place, Mitigations Missing, Proposed High-Risk Mitigations, Remaining Risk.
"""


async def main():
    async with AsyncExitStack() as stack:
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )
        threat_modelling_server = await stack.enter_async_context(
            MCPServerStdio(
                params=threat_modelling_params, client_session_timeout_seconds=60
            )
        )
        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(params=aws_mcp_params, client_session_timeout_seconds=120)
        )

        mcp_servers = [filesystem_mcp_server, threat_modelling_server]
        mcp_servers_with_aws = [
            filesystem_mcp_server,
            threat_modelling_server,
            aws_mcp_server,
        ]

        threat_modelling_tool = initialise_threat_identification_tool(
            mcp_servers=mcp_servers
        )
        risk_assessor_tool = initialise_risk_assessor_tool(mcp_servers=mcp_servers)
        mitigation_planner_tool = initialise_mitigation_planner_tool(
            mcp_servers=mcp_servers
        )
        mitigation_auditor_tool = initialise_mitigation_auditor_tool(
            mcp_servers=mcp_servers_with_aws
        )

        manager_agent = Agent(
            name="Threat modelling coordinator",
            instructions=COORDINATOR_INSTRUCTIONS,
            tools=[
                threat_modelling_tool,
                risk_assessor_tool,
                mitigation_planner_tool,
                mitigation_auditor_tool,
            ],
        )

        with trace("Threat modelling test"):
            result = await Runner.run(
                manager_agent,
                "Run the full threat identification and risk assessment workflow.",
                run_config=run_config(),
                max_turns=50,
            )
            print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
