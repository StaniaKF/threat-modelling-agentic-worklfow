from pathlib import Path
from typing import Any
import typer
from agents import RunConfig, trace
from openai import AsyncOpenAI
from utils.agent_factory import create_agent
from utils.agent_run import run_agent_with_validation
from utils.setup_commands import TODAY, THREATS_JSON_PATH
from validation import validate_after_threat_identifier
from workflow_agent_prompts.threat_identifier import (
    INSTRUCTIONS as THREAT_IDENTIFIER_INSTRUCTIONS,
)


async def identify_threats(
    client: AsyncOpenAI,
    run_config: RunConfig,
    mcp_server: Any,
    diagram: str,
    context: str,
    threats_json_path: Path = THREATS_JSON_PATH,
) -> None:
    """Step 1: Parse documentation and generate initial threat boundaries."""
    typer.echo("\n📋 Step 1/4: Threat Identification")
    agent = create_agent(
        "Threat Identifier Agent", THREAT_IDENTIFIER_INSTRUCTIONS, client, [mcp_server]
    )
    agent_input = f"Today's date: {TODAY}\n\nArchitecture diagram (mermaid):\n{diagram}\n\nBusiness context:\n{context}"

    with trace("Threat Identification"):
        await run_agent_with_validation(
            agent,
            agent_input,
            validate_after_threat_identifier,
            run_config,
            "Threat Identifier",
            threats_json_path=threats_json_path,
        )
