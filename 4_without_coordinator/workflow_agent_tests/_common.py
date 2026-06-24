"""Shared setup helpers for workflow agent test scripts."""

import json
import shutil
from pathlib import Path
from typing import Any

from agents import OpenAIChatCompletionsModel, RunConfig
from agents.tracing import set_trace_processors
from dotenv import load_dotenv

from constants import FILESYSTEM_MCP_PARAMS, MODEL
from utils.agent_factory import create_client
from utils.get_trace import FileSpanExporter

PROJECT_ROOT = Path(__file__).parent.parent
TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
INPUTS_DIR = TESTS_DIR / "inputs"
OUTPUTS_DIR = TESTS_DIR / "outputs"
TRACES_DIR = TESTS_DIR / "traces"
THREATS_JSON_PATH = OUTPUTS_DIR / "threats.json"

TEST_FILESYSTEM_MCP_PARAMS: dict[str, Any] = {
    **FILESYSTEM_MCP_PARAMS,
    "args": ["-y", "@modelcontextprotocol/server-filesystem", str(TESTS_DIR)],
    "cwd": str(TESTS_DIR),
}


def setup(fixture_name: str, trace_filename: str):
    """Load env, seed threats.json, configure tracing. Returns (client, run_config)."""
    load_dotenv(PROJECT_ROOT / ".env")

    OUTPUTS_DIR.mkdir(exist_ok=True)
    TRACES_DIR.mkdir(exist_ok=True)
    shutil.copy(FIXTURES_DIR / fixture_name, OUTPUTS_DIR / "threats.json")
    print(f"Seeded threats.json from {FIXTURES_DIR / fixture_name}")

    set_trace_processors([FileSpanExporter(str(TRACES_DIR / trace_filename))])

    client = create_client()
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client)
    )
    return client, run_config


def read_input(filename: str) -> str:
    path = INPUTS_DIR / filename
    return path.read_text() if path.exists() else ""


def print_threats_summary(label: str = "") -> list:
    data = json.loads((OUTPUTS_DIR / "threats.json").read_text(encoding="utf-8"))
    threats = data.get("threats", [])
    print(f"\n--- {label}: {len(threats)} threats ---")
    return threats
