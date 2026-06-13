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

Create .env file with example values from .env.example 

```bash
cp .env.example .env
# Edit .env with your values

Create context.md file with example values from .env.example 

cp context.md.example context.md
# Edit context.md with your project-specific business context

make install
```

## Business Context (`context.md`)

The `context.md` file provides project-specific business context that helps the agents prioritise threats and mitigations accurately. It is **not committed to the repo** (gitignored) because it changes per project and may contain sensitive details.

Copy the example and fill in your details:

```bash
cp context.md.example context.md
```

The file should include:

- **Project / Service Name** — what the system is called
- **What the system does** — brief description of purpose and data processed
- **Critical Components** — which parts of the architecture matter most and why
- **Sensitive Data** — what PII, secrets, or commercially sensitive data flows through the system
- **Compliance / Regulatory Requirements** — GDPR, PCI-DSS, SOC2, etc.
- **AWS Account Info** — account number, region, and resource physical IDs
- **Trust Assumptions** — what you trust and what you don't
- **Known Gaps / Areas of Concern** — weaknesses the team already suspects

The coordinator reads this file at startup and passes it to every worker agent so they can:
- Focus threat identification on critical components
- Weight risk assessments based on data sensitivity and compliance requirements
- Prioritise mitigations that address known gaps
- Target AWS queries at the correct resources using physical IDs

If `context.md` doesn't exist, the workflow proceeds without it (but results will be less targeted).

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
