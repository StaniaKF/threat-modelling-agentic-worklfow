import os
from typing import NamedTuple

from agents import Agent, OpenAIChatCompletionsModel, Tool
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(__file__), "../.env")
load_dotenv(env_path)

WORKER_MODEL = "openai/gpt-4o-mini"

CLIENT = AsyncOpenAI(
    base_url=os.getenv("LITELLM_API_BASE_URL"),
    api_key=os.getenv("LITELLM_API_KEY"),
    timeout=300.0,
)

threat_modelling_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
filesystem_params = {
    "command": os.getenv("NPX_PATH", "npx"),
    "args": ["-y", "@modelcontextprotocol/server-filesystem", threat_modelling_path],
}
threat_modelling_params = {
    "command": "uvx",
    "args": [
        "--from",
        "git+https://github.com/awslabs/threat-modeling-mcp-server.git",
        "threat-modeling-mcp-server",
    ],
    "client_session_timeout_seconds": 60,
}

aws_mcp_params = {
    "command": os.getenv("UVX_PATH", "uvx"),
    "args": [
        "mcp-proxy-for-aws@latest",
        "https://aws-mcp.eu-central-1.api.aws/mcp",
        "--metadata",
        "AWS_REGION=eu-west-1",
    ],
    "env": {
        "AWS_PROFILE": os.getenv("AWS_PROFILE"),
    },
    "client_session_timeout_seconds": 300,
}


class AgentProperties(NamedTuple):
    name: str
    instructions: str


class ToolProperties(NamedTuple):
    name: str
    description: str


def agent_as_tool(
    agent_properties: AgentProperties,
    tool_properties: ToolProperties,
    mcp_servers: list[MCPServerStdio],
) -> Tool:
    agent = Agent(
        name=agent_properties.name,
        instructions=agent_properties.instructions,
        model=OpenAIChatCompletionsModel(
            model=WORKER_MODEL,
            openai_client=CLIENT,
        ),
        mcp_servers=mcp_servers,
    )

    return agent.as_tool(
        tool_name=tool_properties.name,
        tool_description=tool_properties.description,
        max_turns=50,
    )
