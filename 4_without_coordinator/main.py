"""
Threat modelling CLI — runs the full workflow with validation.

Python orchestrates the pipeline directly (no LLM coordinator). Each agent is
called sequentially with programmatic validation + retry after each step.

- Validates each agent's output programmatically before proceeding to the next step

Requirements:
- An `inputs/` folder in the current directory with: context.md, mermaid.md, cloud-formation.yaml
- Environment variables set (or a .env file in the current directory):
  LITELLM_API_BASE_URL, LITELLM_API_KEY, AWS_PROFILE

Usage:
    uv run threat-model
    uv run python main.py
"""

import asyncio

import typer

from utils.setup_commands import validate_environment, clean_outputs
from utils.workflow_run import run_workflow

app = typer.Typer(
    name="threat-model",
    help="Automated threat modelling pipeline using STRIDE methodology.",
    add_completion=False,
)


@app.command()
def run() -> None:
    """Run the full threat modelling workflow with validation."""
    validate_environment()
    clean_outputs()
    asyncio.run(run_workflow())


if __name__ == "__main__":
    app()
