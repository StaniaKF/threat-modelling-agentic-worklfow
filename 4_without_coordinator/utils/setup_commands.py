import json
import os
import shutil
from datetime import date
from pathlib import Path

import typer
from dotenv import load_dotenv

from utils.messages_printing import print_info, print_error

TODAY = date.today().isoformat()
OUTPUTS_DIR = Path.cwd() / "outputs"
INPUTS_DIR = Path.cwd() / "inputs"
THREATS_JSON_PATH = OUTPUTS_DIR / "threats.json"
REQUIRED_ENV_VARS = ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]


def validate_environment() -> None:
    """Check that required environment variables and input files are present."""
    load_dotenv(Path.cwd() / ".env")

    missing_vars = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
    if missing_vars:
        print_error(
            f"   ❌  Missing required environment variables: {', '.join(missing_vars)}\n"
            f"Set them in your shell or provide a .env file in the current directory."
        )
        raise typer.Exit(1)

    if not INPUTS_DIR.exists():
        print_error(f"   ❌  inputs/ directory not found in {Path.cwd()}")
        raise typer.Exit(1)

    if not (INPUTS_DIR / "mermaid.md").exists():
        print_error("   ❌  inputs/mermaid.md not found. This file is required.")
        raise typer.Exit(1)

    if not (INPUTS_DIR / "context.md").exists():
        print_error("   ❌  inputs/context.md not found. This file is required.")
        raise typer.Exit(1)


def clean_outputs() -> None:
    """Remove and recreate the outputs/ directory.
    This is helpful if you want to start fresh and avoid any leftover files from previous runs.
    """
    if OUTPUTS_DIR.exists():
        shutil.rmtree(OUTPUTS_DIR)
    OUTPUTS_DIR.mkdir(exist_ok=True)
    print_info(f"📁 Cleaned outputs directory: {OUTPUTS_DIR}")


def read_input(filename: str) -> str:
    """Read an input file, returning empty string if it doesn't exist."""
    path = INPUTS_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def create_initial_threats_json(service_project: str) -> None:
    """Create the initial threats.json with metadata."""
    data = {
        "metadata": {
            "date_of_analysis": TODAY,
            "service_project": service_project,
        },
        "threats": [],
    }
    THREATS_JSON_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print_info(f"📄 Created initial outputs/threats.json (service: {service_project})")
