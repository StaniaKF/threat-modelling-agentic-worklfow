import json
import os
from pathlib import Path
from typing import Any, Callable, NamedTuple

from agents import Agent, OpenAIChatCompletionsModel, Runner, RunConfig, Tool, function_tool
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

threat_modelling_path = os.getcwd()

filesystem_params: dict[str, Any] = {
    "command": os.getenv("NPX_PATH", "npx"),
    "args": ["-y", "@modelcontextprotocol/server-filesystem", threat_modelling_path],
}

aws_mcp_params: dict[str, Any] = {
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
    mcp_servers: list[MCPServerStdio] | None = None,
) -> Tool:
    agent = Agent(
        name=agent_properties.name,
        instructions=agent_properties.instructions,
        model=OpenAIChatCompletionsModel(
            model=WORKER_MODEL,
            openai_client=CLIENT,
        ),
        mcp_servers=mcp_servers or [],
    )

    return agent.as_tool(
        tool_name=tool_properties.name,
        tool_description=tool_properties.description,
        max_turns=50,
    )


# Path to threats.json used for snapshotting pre-state
THREATS_JSON_PATH = Path.cwd() / "outputs" / "threats.json"


def agent_as_tool_with_validation(
    agent_properties: AgentProperties,
    tool_properties: ToolProperties,
    validator: Callable[[int], str | None],
    mcp_servers: list[MCPServerStdio] | None = None,
    max_retries: int = 2,
) -> Tool:
    """Wrap an agent as a tool with post-execution validation and retry.

    Args:
        agent_properties: Name and instructions for the worker agent.
        tool_properties: Tool name and description exposed to the coordinator.
        validator: A callable that takes the expected threat count (int) and returns
                   None if valid, or a string of errors if invalid.
                   For the threat identifier (no expected count), pass a wrapper
                   that ignores the argument.
        mcp_servers: MCP servers to attach to the worker agent.
        max_retries: Number of times to retry on validation failure (default 2).
    """

    agent = Agent(
        name=agent_properties.name,
        instructions=agent_properties.instructions,
        model=OpenAIChatCompletionsModel(
            model=WORKER_MODEL,
            openai_client=CLIENT,
        ),
        mcp_servers=mcp_servers or [],
    )

    @function_tool(
        name_override=tool_properties.name,
        description_override=tool_properties.description,
    )
    async def validated_tool(input: str) -> str:
        """Agent tool with validation and retry logic."""
        run_config = RunConfig(
            model=OpenAIChatCompletionsModel(model=WORKER_MODEL, openai_client=CLIENT),
        )

        # Snapshot the threat count before the agent runs
        pre_threat_count = 0
        if THREATS_JSON_PATH.exists():
            try:
                pre_data = json.loads(THREATS_JSON_PATH.read_text(encoding="utf-8"))
                pre_threat_count = len(pre_data.get("threats", []))
            except (json.JSONDecodeError, KeyError):
                pass

        validation_error: str | None = None

        for attempt in range(1 + max_retries):
            # On retry, append the validation errors to the input
            if attempt == 0:
                message = input
            else:
                message = (
                    f"{input}\n\n"
                    f"⚠️ VALIDATION FAILED (attempt {attempt}/{max_retries}). "
                    f"Your previous output did not pass validation.\n"
                    f"Errors:\n{validation_error}\n\n"
                    f"Please re-read threats.json and fix these specific issues."
                )

            result = await Runner.run(
                agent, message, run_config=run_config, max_turns=50
            )

            # Run the validator with the pre-run threat count as the expected count.
            # For threat_identifier: pre_threat_count is 0, and its validator ignores it.
            # For other agents: they verify the count hasn't changed.
            validation_error = validator(pre_threat_count)

            if validation_error is None:
                print(f"[{agent_properties.name}] ✓ Validation passed (attempt {attempt + 1})")
                return result.final_output or "Done — validation passed."

            print(
                f"[{agent_properties.name}] ✗ Validation failed (attempt {attempt + 1}/{1 + max_retries}):\n"
                f"  {validation_error[:200]}"
            )

        return (
            f"VALIDATION FAILED after {1 + max_retries} attempts. "
            f"Last errors:\n{validation_error}"
        )

    return validated_tool
