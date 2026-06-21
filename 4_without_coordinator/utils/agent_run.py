import json

import typer
from agents import Agent, RunConfig, Runner

from constants import MAX_RETRIES
from utils.setup_commands import THREATS_JSON_PATH


def _get_current_threat_count() -> int:
    """Fetch the current number of threats from outputs/threats.json."""
    if not THREATS_JSON_PATH.exists():
        return 0
    try:
        threat_data = json.loads(THREATS_JSON_PATH.read_text(encoding="utf-8"))
        return len(threat_data.get("threats", []))
    except json.JSONDecodeError, KeyError, TypeError:
        return 0


def _build_agent_prompt(
    input_message: str, attempt: int, validation_error: str | None
) -> str:
    """Constructs either the initial prompt or a retry prompt with validation errors."""
    if attempt == 0 or not validation_error:
        return input_message

    return (
        f"{input_message}\n\n"
        f"⚠️ VALIDATION FAILED (attempt {attempt}/{MAX_RETRIES}). "
        f"Your previous output did not pass validation.\n"
        f"Errors:\n{validation_error}\n\n"
        f"Please re-read outputs/threats.json and fix these specific issues."
    )


async def run_agent_with_validation(
    agent: Agent,
    input_message: str,
    validator,
    run_config: RunConfig,
    agent_name: str,
) -> None:
    """Run an agent (streamed) with validation and retry logic.

    Streams the agent's output to stdout in real-time, then validates
    the resulting threats.json. Retries on validation failure.
    """
    threat_count = _get_current_threat_count()

    validation_error: str | None = None

    for attempt in range(1 + MAX_RETRIES):
        message = _build_agent_prompt(input_message, attempt, validation_error)

        typer.echo(f"  🔄 Running {agent_name} (attempt {attempt + 1})...")

        # Start the stream
        result = Runner.run_streamed(
            agent, message, run_config=run_config, max_turns=50
        )
        # Consume the stream and print to stdout
        async for event in result.stream_events():
            if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                print(event.data.delta, end="", flush=True)
        print()  # Newline after stream ends

        # Validate after the agent has fully completed
        validation_error = validator(threat_count)

        # When no validation errors are found, exit early
        if validation_error is None:
            typer.echo(f"  ✓ {agent_name} — validation passed")
            return

        typer.echo(f"  ✗ {agent_name} — validation failed: {validation_error[:150]}")

    typer.echo(f"❌ {agent_name} FAILED after {1 + MAX_RETRIES} attempts.", err=True)
    typer.echo(f"   Last errors: {validation_error}", err=True)
    raise typer.Exit(1)
