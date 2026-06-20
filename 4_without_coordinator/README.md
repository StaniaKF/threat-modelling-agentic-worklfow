# Threat Modelling Agentic Workflow — No Coordinator

An automated threat modelling pipeline built with the OpenAI Agents SDK. Python orchestrates specialist worker agents directly (no LLM coordinator) with programmatic validation after each step.

1. **Identify threats** using STRIDE methodology
2. **Assess risk** — agent assesses impact + likelihood; risk computed deterministically from matrix
3. **Plan mitigations** — proposes 4-8 controls per threat
4. **Audit mitigations** — checks which controls are in place via the AWS MCP server

## Why No Coordinator?

The workflow is linear and fixed. A Python script calling each agent sequentially is:
- **Cheaper** — no LLM calls just to decide "call the next tool"
- **Faster** — no round-trips for the coordinator to think
- **More reliable** — no parallel execution bugs, no infinite retry loops
- **Simpler** — the orchestration logic is visible in `main.py`, not hidden in a prompt

## Setup

```bash
cp .env.example .env
# Edit .env with your values

mkdir inputs
cp context.md.example inputs/context.md
# Edit inputs/context.md
# Add inputs/mermaid.md (architecture diagram, required)
# Add inputs/cloud-formation.yaml (AWS resources, optional)

make install
```

## Running

```bash
aws sso login
uv run threat-model
```

Or directly:
```bash
uv run python main.py
```

### Building and Installing as a Package

```bash
uv build
pip install dist/threat_modelling_agentic_worklfow-0.1.0-py3-none-any.whl
threat-model  # run from any directory with inputs/ and .env
```

## Directory Layout

```
├── main.py                          # CLI + workflow orchestration
├── worker_agents/
│   ├── common.py                    # MCP server params, model config
│   ├── threat_identifier.py         # STRIDE threat identification instructions
│   ├── risk_assessor.py             # Impact/likelihood assessment instructions
│   ├── mitigation_planner.py        # Mitigation proposal instructions
│   └── mitigation_auditor.py        # AWS audit instructions
├── validation/
│   ├── __init__.py
│   └── validators.py                # Programmatic validators + risk matrix
├── tools/
│   └── convert_to_csv.py            # JSON → pipe-delimited CSV
├── utils/
│   └── get_trace.py                 # Local trace file exporter
├── worker_agent_tests/              # Integration tests for individual agents
│   ├── fixtures/                    # Pre-built JSON states for each stage
│   ├── test_threat_identifier.py
│   ├── test_risk_assessor.py
│   ├── test_mitigation_planner.py
│   └── test_mitigation_auditor.py
├── inputs/                          # Your project-specific inputs (gitignored)
│   ├── context.md
│   ├── mermaid.md
│   └── cloud-formation.yaml
├── outputs/                         # Generated (gitignored, cleaned each run)
│   ├── threats.json
│   ├── threats.csv
│   ├── analysis.md
│   └── trace_output.json
└── .env                             # API keys (gitignored)
```

## Validation System

After each agent writes `outputs/threats.json`, a Python validator checks correctness:

| Agent | Validator checks |
|-------|-----------------|
| Threat Identifier | Non-empty threats, 4 required fields, valid STRIDE categories |
| Risk Assessor | Impact/likelihood valid; **risk computed from matrix in code** |
| Mitigation Planner | 1-10 mitigations per threat, all non-empty strings |
| Mitigation Auditor | in_place + missing = all_possible, remaining_risk valid |

On failure, the agent is re-invoked with the specific errors (up to 2 retries).

## Testing Individual Agents

```bash
uv run python -m worker_agent_tests.test_threat_identifier
uv run python -m worker_agent_tests.test_risk_assessor
uv run python -m worker_agent_tests.test_mitigation_planner
uv run python -m worker_agent_tests.test_mitigation_auditor
```

Tests seed fixtures to `outputs/threats.json` and run the agent in isolation.

## Available Commands

| Command        | Description                              |
|----------------|------------------------------------------|
| `make install` | Install all dependencies (including dev) |
| `make lint`    | Check for linting and formatting issues  |
| `make format`  | Auto-fix formatting issues               |
