from pathlib import Path
from typing import Any
import typer
from agents import RunConfig, trace
from openai import AsyncOpenAI
from utils.agent_factory import create_agent
from utils.agent_run import run_agent_with_validation
from utils.setup_commands import THREATS_JSON_PATH
from validation import validate_after_risk_assessor
from workflow_agents.risk_assessor import INSTRUCTIONS as RISK_ASSESSOR_INSTRUCTIONS


async def assess_risks(
    client: AsyncOpenAI,
    run_config: RunConfig,
    mcp_server: Any,
    context: str,
    cloudformation: str,
    threats_json_path: Path = THREATS_JSON_PATH,
) -> None:
    """Step 2: Cross-reference threat modeling with CloudFormation files to map overall risk vectors."""
    typer.echo("\n📊 Step 2/4: Risk Assessment")
    agent = create_agent(
        "Risk Assessor Agent", RISK_ASSESSOR_INSTRUCTIONS, client, [mcp_server]
    )
    agent_input = f"Business context:\n{context}\n\nCloudFormation resource definitions:\n{cloudformation}"

    with trace("Risk Assessment"):
        await run_agent_with_validation(
            agent,
            agent_input,
            validate_after_risk_assessor,
            run_config,
            "Risk Assessor",
            threats_json_path=threats_json_path,
        )
