import os
import asyncio
from contextlib import AsyncExitStack

from agents import Runner, RunConfig, OpenAIChatCompletionsModel, trace
from agents.tracing import set_trace_processors
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

from utils.get_trace import FileSpanExporter

from coordinator_agent import initialise_coordinator_agent
from worker_agents import (
    initialise_threat_identification_tool,
    initialise_risk_assessor_tool,
    initialise_mitigation_planner_tool,
    initialise_mitigation_auditor_tool,
    filesystem_params,
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


async def main() -> None:
    # Set up local trace exporter
    set_trace_processors([FileSpanExporter("trace_output.json")])

    async with AsyncExitStack() as stack:
        # Filesystem server - only used by the coordinator
        filesystem_mcp_server = await stack.enter_async_context(
            MCPServerStdio(filesystem_params)
        )

        # AWS MCP server - used only by the mitigation auditor
        # Filter out aws___run_script as it uses call_boto3() which doesn't recognise
        # standard operation names. The agent should use aws___call_aws instead.
        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(
                params=aws_mcp_params,
                client_session_timeout_seconds=300,
                tool_filter=lambda tool, ctx: tool.name != "aws___run_script",
            )
        )

        # Warm up AWS MCP server to avoid cold-start delays
        print("Warming up AWS MCP server...")
        aws_tools = await aws_mcp_server.list_tools()
        print(f"AWS MCP server ready. {len(aws_tools)} tools available.")

        # Worker agents — threat identifier, risk assessor, and mitigation planner
        # don't need MCP servers (they use LLM knowledge only)
        threat_modelling_tool = initialise_threat_identification_tool()
        risk_assessor_tool = initialise_risk_assessor_tool()
        mitigation_planner_tool = initialise_mitigation_planner_tool()

        # Mitigation auditor needs the AWS MCP server to query live resources
        mitigation_auditor_tool = initialise_mitigation_auditor_tool(
            mcp_servers=[aws_mcp_server]
        )

        # Coordinator gets filesystem access + all worker tools
        coordinator_tools = [
            threat_modelling_tool,
            risk_assessor_tool,
            mitigation_planner_tool,
            mitigation_auditor_tool,
        ]
        coordinator_agent = initialise_coordinator_agent(
            mcp_servers=[filesystem_mcp_server],
            tools=coordinator_tools,
        )

        with trace("Threat modelling workflow"):
            result = await Runner.run(
                coordinator_agent,
                "Run the full threat identification and risk assessment workflow.",
                run_config=run_config(),
                max_turns=50,
            )
            print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
