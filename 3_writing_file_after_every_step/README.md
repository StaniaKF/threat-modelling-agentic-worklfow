# Threat Modelling Agentic Workflow — with AWS MCP Server

An automated threat modelling pipeline built with the OpenAI Agents SDK. A coordinator agent orchestrates specialist worker agents that use MCP (Model Context Protocol) servers to:

1. **Identify threats** in a system architecture using the STRIDE methodology
2. **Assess risk** by evaluating impact and likelihood for each threat
3. **Plan mitigations** by proposing controls for high-risk threats
4. **Audit mitigations** by checking which controls are already in place via the AWS MCP server

The workflow reads a Mermaid architecture diagram, runs the full analysis pipeline, and outputs a structured threat model as JSON and CSV in the `outputs/` folder.

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

cp context.md.example context.md
# Edit context.md with your project-specific business context

make install
```

## Running

Log in to AWS first:
```bash
aws sso login
```

**Without validation** (basic workflow):
```bash
uv run python main.py
```

**With validation** (recommended — includes programmatic checks and retry):
```bash
uv run python main_with_validation.py
```

Both write outputs to `outputs/` (threats.json, threats.csv, analysis.md, trace).

## Validation System

`main_with_validation.py` wraps each worker agent with a programmatic validation step. After each agent writes `outputs/threats.json`, a Python validator reads the file and checks it for correctness. If validation fails, the agent is automatically re-invoked with the specific errors appended to its input (up to 2 retries).

### What each validator checks

| Agent | Validator checks |
|-------|-----------------|
| Threat Identifier | Threats array is non-empty, all 4 required fields present and non-null, valid STRIDE categories |
| Risk Assessor | Threat count preserved (no truncation), impact/likelihood/risk are non-null, **risk correctly matches the defined matrix** (e.g. Impact=High + Likelihood=Medium must equal Risk=High) |
| Mitigation Planner | Threat count preserved, `all_possible_mitigations` is a non-empty array of strings for every threat |
| Mitigation Auditor | Threat count preserved, `mitigations_already_in_place` + `mitigations_missing` count equals `all_possible_mitigations` count, `remaining_risk` is a valid level |

### How retries work

1. Agent runs and writes to `outputs/threats.json`
2. Validator reads the file and checks constraints
3. If valid → proceed to next agent
4. If invalid → agent is re-invoked with the original input + error details (e.g. "Threat 3: risk is 'Medium' but matrix says Impact=High + Likelihood=Medium → 'High'")
5. Up to 2 retries (3 attempts total) before reporting failure

### Why not SDK guardrails?

The OpenAI Agents SDK has a guardrails feature, but it's designed for checking the agent's response text (content safety, PII). Our agents' real output is a file on disk (written via MCP tools), not their response text. Additionally, guardrails halt on failure — they don't retry. The custom validation wrapper gives us file-level checks with feedback-driven retries.

## Project Structure

```
├── main.py                          # Basic workflow (no validation)
├── main_with_validation.py          # Workflow with validation + retry
├── coordinator_agent.py             # Coordinator agent definition
├── worker_agents/
│   ├── common.py                    # Shared config, agent_as_tool, agent_as_tool_with_validation
│   ├── threat_identifier.py         # STRIDE threat identification
│   ├── risk_assessor.py             # Impact/likelihood/risk assessment
│   ├── mitigation_planner.py        # Mitigation proposals
│   └── mitigation_auditor.py        # AWS audit of mitigations in place
├── validation/
│   ├── __init__.py
│   └── validators.py                # Programmatic validators for each agent step
├── tools/
│   └── convert_to_csv.py            # JSON → pipe-delimited CSV converter
├── utils/
│   └── get_trace.py                 # Local trace file exporter
├── outputs/                         # Generated outputs (gitignored)
│   ├── threats.json
│   ├── threats.csv
│   ├── analysis.md
│   └── trace_output*.json
├── context.md                       # Business context (gitignored, project-specific)
├── mermaid.md                       # Architecture diagram
└── cloud-formation.yaml             # AWS resource definitions (gitignored)
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
- **Critical Components** — which parts of the architecture matter most and why (include physical IDs)
- **Sensitive Data** — what PII, secrets, or commercially sensitive data flows through the system
- **Compliance / Regulatory Requirements** — GDPR, PCI-DSS, SOC2, etc.
- **AWS Account Info** — account number, region, and resource physical IDs
- **Trust Assumptions** — what you trust and what you don't

## CloudFormation File (`cloud-formation.yaml`)

Provides the agents with actual AWS resource definitions. Helps them understand the intended configuration so they can identify threats and verify mitigations against live state.

- Include security-relevant resources: IAM roles/policies, security groups, Lambda functions, API Gateways, caches, VPCs, etc.
- No need for perfect formatting — agents can handle imperfect YAML
- If `cloud-formation.yaml` doesn't exist, the workflow proceeds without it

## Available Commands

| Command        | Description                              |
|----------------|------------------------------------------|
| `make install` | Install all dependencies (including dev) |
| `make lint`    | Check for linting and formatting issues  |
| `make format`  | Auto-fix formatting issues               |

## Key Design Decisions

1. **JSON over CSV** — agents work with `threats.json` as the shared data format (models handle JSON far more reliably than positional tabular formats)
2. **Sequential execution** — `ModelSettings(parallel_tool_calls=False)` on the coordinator prevents race conditions where agents read stale data
3. **Programmatic validation** — deterministic Python checks catch errors that prompt-based instructions alone cannot reliably prevent
4. **Outputs folder** — all generated files go to `outputs/`, cleaned at the start of each run
5. **Workers have filesystem MCP** — agents read/write directly instead of relaying through the coordinator (avoids timeout and truncation issues)
