import json
from pathlib import Path

import typer
from agents import Agent, RunConfig, Runner
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown

from constants import MAX_RETRIES
from utils.messages_printing import print_info, print_success, print_error
from utils.setup_commands import THREATS_JSON_PATH

_console = Console()


def _get_current_threat_count(threats_json_path: Path | None = None) -> int:
    """Fetch the current number of threats from threats.json."""
    path = threats_json_path if threats_json_path is not None else THREATS_JSON_PATH
    if not path.exists():
        return 0
    try:
        threat_data = json.loads(path.read_text(encoding="utf-8"))
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
    threats_json_path: Path | None = None,
) -> None:
    """Run an agent (streamed) with validation and retry logic.

    Streams the agent's output to stdout in real-time, then validates
    the resulting threats.json. Retries on validation failure.
    """
    path = threats_json_path if threats_json_path is not None else THREATS_JSON_PATH
    threat_count = _get_current_threat_count(path)

    validation_error: str | None = None

    for attempt in range(1 + MAX_RETRIES):
        message = _build_agent_prompt(input_message, attempt, validation_error)

        print_info(f"  🔄 Running {agent_name} (attempt {attempt + 1})...")

        # Start the stream
        result = Runner.run_streamed(
            agent, message, run_config=run_config, max_turns=50
        )
        # Consume the stream and render as markdown in real-time
        streamed_text = ""
        with Live(Markdown(""), console=_console, refresh_per_second=8) as live:
            async for event in result.stream_events():
                if event.type == "raw_response_event" and hasattr(event.data, "delta"):
                    streamed_text += event.data.delta
                    live.update(Markdown(streamed_text))

        # Validate after the agent has fully completed
        validation_error = validator(threat_count, path)

        # When no validation errors are found, exit early
        if validation_error is None:
            print_success(f"  ✓ {agent_name} — validation passed")
            return

        print_error(f"  ✗ {agent_name} — validation failed: {validation_error[:150]}")

    print_error(f"❌ {agent_name} FAILED after {1 + MAX_RETRIES} attempts.")
    print_error(f"   Last errors: {validation_error}")
    raise typer.Exit(1)
