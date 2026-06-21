"""
Shared configuration for worker agents: MCP server params and model settings.
"""

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

MODEL = "openai/gpt-4o-mini"
MAX_RETRIES = 2

THREAT_MODELLING_PATH = os.getcwd()

FILESYSTEM_MCP_PARAMS: dict[str, Any] = {
    "command": os.getenv("NPX_PATH", "npx"),
    "args": ["-y", "@modelcontextprotocol/server-filesystem", THREAT_MODELLING_PATH],
}

AWS_MCP_PARAMS: dict[str, Any] = {
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
