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

### 1. Install dependencies

```bash
make install
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in the following:

**`LITELLM_API_BASE_URL` and `LITELLM_API_KEY`** — the LiteLLM proxy endpoint and key.
See the internal setup guide: [Creating a LiteLLM API key](https://notion.so/kraken-tech/Creating-a-LiteLLM-API-key-32873c742c71800cbca2f43dacc00f34)

**`OPENAI_API_KEY`** — two options:
- Set to any non-empty string (e.g. `unused`) when routing all calls through LiteLLM. Traces are saved locally to `outputs/traces/` only.
- Set to a real OpenAI API key if you want traces sent to the [OpenAI trace dashboard](https://platform.openai.com/traces) in addition to the local file.

**`AWS_PROFILE`** — the AWS SSO profile used by the Mitigation Auditor to query live infrastructure.

**`NPX_PATH` / `UVX_PATH`** — optional. Only needed if `npx` or `uvx` are not on your `PATH`.

### 3. Add your input files

```bash
mkdir inputs
```

Create the following files inside `inputs/`:

- **`context.md`** — describe your service and its business context (architecture overview, data sensitivity, deployment environment), follow the structure of context.md.example (required)
- **`mermaid.md`** — architecture diagram in Mermaid syntax (required)
- **`cloud-formation.yaml`** — AWS resource definitions (optional but recommended for the audit step), it does not need to be a complete template, just the resources you want to check. It will ignore incomplete Imports or variables.

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
├── main.py                          # CLI entry point (validate, clean, run)
├── constants.py                     # Model config, MCP server params, retry limits
├── workflow_agent_prompts/
│   ├── threat_identifier.py         # STRIDE threat identification instructions
│   ├── risk_assessor.py             # Impact/likelihood assessment instructions
│   ├── mitigation_planner.py        # Mitigation proposal instructions
│   └── mitigation_auditor.py        # AWS audit instructions
├── workflow_steps/
│   ├── threat_identification.py     # Step 1 — runs threat identifier + validation
│   ├── risk_assessment.py           # Step 2 — runs risk assessor + validation
│   ├── mitigation_planning.py       # Step 3 — runs mitigation planner + validation
│   └── mitigation_auditing.py       # Step 4 — runs mitigation auditor per threat + validation
├── utils/
│   ├── agent_run.py                 # Agent execution with retry + validation loop
│   ├── agent_factory.py             # Agent and client construction helpers
│   ├── setup_commands.py            # Environment validation, file helpers
│   ├── get_trace.py                 # Local trace file exporter
│   ├── parsers.py                   # Output parsing helpers
│   └── from_json_to_csv_converter.py  # JSON → pipe-delimited CSV
├── validation/
│   └── validators.py                # Programmatic validators + risk matrix
├── tests/
│   └── unit/                        # Unit tests (100% coverage), written by Claude 
│       ├── conftest.py
│       ├── test_main.py
│       ├── test_setup_commands.py
│       ├── test_agent_run.py
│       ├── test_validators.py
│       ├── test_get_trace.py
│       └── test_convert_to_csv.py
├── workflow_agent_tests/            # Integration tests for individual agents (LLM calls)
│   ├── fixtures/                    # Pre-built JSON states for each pipeline stage
│   ├── inputs/                      # Symlink to inputs/ (gitignored)
│   ├── outputs/                     # threats.json written by agent under test (gitignored)
│   ├── traces/                      # Per-test trace files (gitignored)
│   ├── _common.py                   # Shared setup: seeding, tracing, MCP params
│   ├── test_threat_identifier.py
│   ├── test_risk_assessor.py
│   ├── test_mitigation_planner.py
│   └── test_mitigation_auditor.py
├── inputs/                          # Your project-specific inputs (gitignored)
│   ├── context.md
│   ├── mermaid.md
│   └── cloud-formation.yaml
├── outputs/                         # Generated by main workflow (gitignored, cleaned each run)
│   ├── threats.json
│   ├── threats.csv
│   └── traces/                      # Per-agent trace files
│       ├── trace_threat_identifier.json
│       ├── trace_risk_assessor.json
│       ├── trace_mitigation_planner.json
│       └── trace_mitigation_auditor.json
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
uv run python -m workflow_agent_tests.test_threat_identifier
uv run python -m workflow_agent_tests.test_risk_assessor
uv run python -m workflow_agent_tests.test_mitigation_planner
uv run python -m workflow_agent_tests.test_mitigation_auditor
```

Each test seeds a fixture from `workflow_agent_tests/fixtures/` into `workflow_agent_tests/outputs/threats.json`, runs the agent in isolation, and writes a trace to `workflow_agent_tests/traces/`.

## Available Commands

| Command        | Description                                               |
|----------------|-----------------------------------------------------------|
| `make install` | Install all dependencies (including dev)                  |
| `make test`    | Run unit tests with coverage (enforces 100%)              |
| `make lint`    | Check for linting and formatting issues                   |
| `make format`  | Auto-fix formatting issues                                |
