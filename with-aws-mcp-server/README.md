# Threat Modelling Agentic Workflow — with AWS MCP Server

An automated threat modelling pipeline built with the OpenAI Agents SDK. A coordinator agent orchestrates specialist worker agents that use MCP (Model Context Protocol) servers to:

1. **Identify threats** in a system architecture using the STRIDE methodology
2. **Assess risk** by evaluating impact and likelihood for each threat
3. **Plan mitigations** by proposing controls for high-risk threats
4. **Audit mitigations** by checking which controls are already in place via the AWS MCP server

The workflow reads a Mermaid architecture diagram, runs the full analysis pipeline, and outputs a structured threat model as a CSV.

## Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) package manager
- Node.js (for the filesystem MCP server)
- An AWS profile with access to the target account
- A LiteLLM proxy (or compatible OpenAI API endpoint)

## Setup

```bash
cp .env.example .env
# Edit .env with your values
make install
```

## Available commands

| Command        | Description                                      |
|----------------|--------------------------------------------------|
| `make install` | Install all dependencies (including dev)         |
| `make lint`    | Check for linting and formatting issues          |
| `make format`  | Auto-fix formatting issues                       |

## Running

```bash
uv run python main.py
```
