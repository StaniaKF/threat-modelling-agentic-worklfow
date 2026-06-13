import os
import asyncio
from datetime import date
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


TODAY = date.today().isoformat()  # e.g. "2025-06-13"

COORDINATOR_INSTRUCTIONS = f"""
    You are a threat modelling coordinator. Your job is to orchestrate specialist agents to produce a comprehensive threat model.

    TODAY'S DATE: {TODAY}
    Always pass this date to the threat_identification agent so it can use it in the "Date of analysis" column.

    You have access to the filesystem MCP server to read/write files, and these agent tools:
    - threat_identification: Identifies threats using STRIDE methodology
    - risk_assessment: Assesses impact, likelihood, and risk level for identified threats
    - mitigation_planning: Identifies all possible mitigations and proposes high-risk missing mitigations
    - mitigation_audit: Checks which mitigations are already in place on AWS and which are missing

    IMPORTANT: You are the ONLY agent with filesystem access. Worker agents do NOT have filesystem access.
    You must read files and pass their content to the workers, and write results back to files yourself.

    Workflow - execute in this exact order:
    1. Read context.md using the filesystem read_file tool. This contains business context about
       what's critical, what data is sensitive, compliance requirements, and known gaps.
       If context.md does not exist, proceed without it.
    2. Read the mermaid.md architecture diagram using the filesystem read_file tool.
    3. Call threat_identification, passing it:
       - Today's date ({TODAY}) for the "Date of analysis" column
       - The full content of the mermaid.md diagram
       - The business context from context.md (so it knows what's critical)
       It will return identified threats.
    4. Write the initial threats.csv using the filesystem write_file tool based on the output from step 3.
       Use PIPE (|) as delimiter. Header row:
       Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|Mitigations Already in Place|Mitigations Missing|AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk
    5. Read the threats.csv you just wrote, then call risk_assessment passing it:
       - The CSV content
       - The business context from context.md (so it can weigh impact appropriately)
       It will return assessments. Update threats.csv with the Impact, Likelihood, and Risk columns.
    6. Read the updated threats.csv, then call mitigation_planning passing it:
       - The CSV content
       - The business context from context.md (so it knows compliance requirements and known gaps)
       It will return mitigations. Update threats.csv with the All Possible Mitigations and
       AI Proposed High-Risk Missing Mitigations columns.
    7. Read the updated threats.csv, then call mitigation_audit passing it:
       - The CSV content
       - The mermaid.md diagram content
       - The business context from context.md (so it knows what AWS resources to check)
       It will query AWS to check what's in place.
       Update threats.csv with the Mitigations Already in Place, Mitigations Missing, and Remaining Risk columns.
    8. Present the final results clearly.

    Rules:
    - Execute tools in the exact order above. Each depends on the previous outputs.
    - You handle ALL file reading and writing. Workers only analyse and return results.
    - Always pass the business context to every worker so they can prioritise correctly.
    - Do not perform any analysis yourself - only use the tools.
    - Do not ask the user for any input.
    - The final output should cover: STRIDE Category, Element, Threat, Attack Method, Impact, Likelihood, Risk, All Possible Mitigations, Mitigations In Place, Mitigations Missing, Proposed High-Risk Mitigations, Remaining Risk.
"""


async def main():
    async with AsyncExitStack() as stack:
        # Filesystem server - only used by the coordinator
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        # Threat modelling server - used by threat identifier, risk assessor, and mitigation planner
        threat_modelling_server = await stack.enter_async_context(
            MCPServerStdio(
                params=threat_modelling_params, client_session_timeout_seconds=60
            )
        )

        # AWS MCP server - used only by the mitigation auditor
        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(params=aws_mcp_params, client_session_timeout_seconds=300)
        )

        # Warm up AWS MCP server to avoid cold-start delays
        print("Warming up AWS MCP server...")
        aws_tools = await aws_mcp_server.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.")

        # Worker agents get only the MCP servers they need (keeps tool count under 128)
        threat_modelling_tool = initialise_threat_identification_tool(
            mcp_servers=[threat_modelling_server]
        )
        risk_assessor_tool = initialise_risk_assessor_tool(
            mcp_servers=[threat_modelling_server]
        )
        mitigation_planner_tool = initialise_mitigation_planner_tool(
            mcp_servers=[threat_modelling_server]
        )
        mitigation_auditor_tool = initialise_mitigation_auditor_tool(
            mcp_servers=[aws_mcp_server]
        )

        # Coordinator gets filesystem access + all worker tools
        manager_agent = Agent(
            name="Threat modelling coordinator",
            instructions=COORDINATOR_INSTRUCTIONS,
            mcp_servers=[filesystem_mcp_server],
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
