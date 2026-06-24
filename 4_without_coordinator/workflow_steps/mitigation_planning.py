from pathlib import Path
from typing import Any
import typer
from agents import RunConfig, trace
from openai import AsyncOpenAI
from utils.agent_factory import create_agent
from utils.agent_run import run_agent_with_validation
from utils.setup_commands import THREATS_JSON_PATH
from validation import validate_after_mitigation_planner
from workflow_agents.mitigation_planner import (
    INSTRUCTIONS as MITIGATION_PLANNER_INSTRUCTIONS,
)


async def plan_mitigations(
    client: AsyncOpenAI,
    run_config: RunConfig,
    mcp_server: Any,
    threats_json_path: Path = THREATS_JSON_PATH,
) -> None:
    """Step 3: Devise strategic actionable fixes for the found vulnerabilities."""
    typer.echo("\n🛡️ Step 3/4: Mitigation Planning")
    agent = create_agent(
        "Mitigation Planner Agent",
        MITIGATION_PLANNER_INSTRUCTIONS,
        client,
        [mcp_server],
    )

    with trace("Mitigation Planning"):
        await run_agent_with_validation(
            agent,
            "",
            validate_after_mitigation_planner,
            run_config,
            "Mitigation Planner",
            threats_json_path=threats_json_path,
        )
