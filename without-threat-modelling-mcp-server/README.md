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

## CloudFormation File (`cloud-formation.yaml`)

The `cloud-formation.yaml` file provides the agents with actual AWS resource definitions as additional context alongside the architecture diagram and live AWS queries. It helps agents understand the intended configuration of resources so they can identify threats and propose mitigations more accurately.

This file is **not committed to the repo** (gitignored) because it contains infrastructure details specific to your project.

Create it manually by copying the relevant resource definitions from your CloudFormation stacks into a single file:

- Include all **security-relevant resources**: IAM roles/policies, security groups, Lambda functions, API Gateways, databases, caches, VPCs, S3 buckets, KMS keys, WAF rules, etc.
- **No need to include** non-security resources like CloudWatch alarms, dashboards, or tags-only resources.
- **No need for correct formatting** — the agents can parse imperfect YAML. Just paste the resource blocks in.
- **No parameters section needed** — if your templates use `!ImportValue` or parameter refs that aren't defined in the file, the agents will ignore them or resolve the actual values via the AWS MCP server.
- Keep it to **one file** with all important resources consolidated.

The coordinator reads this file at startup and passes it to every worker agent so they can:
- Identify threats based on actual misconfigurations (not assumptions)
- Assess risk more accurately by knowing what's already configured
- Propose specific mitigations referencing real resource properties
- Cross-reference expected configuration against live AWS state to detect drift

If `cloud-formation.yaml` doesn't exist, the workflow proceeds without it.

## Available commands

| Command        | Description                                      |
|----------------|--------------------------------------------------|
| `make install` | Install all dependencies (including dev)         |
| `make lint`    | Check for linting and formatting issues          |
| `make format`  | Auto-fix formatting issues                       |

## Running

first log in to aws
```bash
aws sso login
```

```bash
uv run python main.py
```

## Limitations of this workflow

### CSV column misalignment (primary issue)

The biggest reliability problem is that worker agents (especially the mitigation auditor) struggle to maintain correct column structure in the pipe-delimited CSV. The CSV has 14 columns, and when the model generates long rows with detailed content in each field, it frequently miscounts pipe delimiters — merging columns, dropping them, or shifting content into wrong positions.

This happens because:
- Each row can be 500+ characters long with semicolons, numbered lists, and descriptive text within individual fields
- Smaller models (gpt-4o-mini) have difficulty tracking positional structure in very wide tabular data
- The model confuses semicolons within mitigations (used as list separators) with structural boundaries

### Coordinator relay bottleneck

Worker agents don't have filesystem access — they return their full output to the coordinator, which then writes it to `threats.csv`. This creates two problems:

1. **Timeout risk**: The auditor must generate all 14+ rows of detailed CSV in a single LLM response. If this takes longer than the LiteLLM proxy timeout (default 120s), the connection drops mid-stream and the entire run fails.
2. **Coordinator may forget to write**: After receiving the auditor's output (the final step), the coordinator sometimes skips the file write and just presents a summary — losing all the auditor's work.

### AWS MCP proxy limitations

- Some AWS services are not supported by `mcp-proxy-for-aws` (e.g. AWS Config, GuardDuty, SecurityHub). The auditor must fall back to CloudFormation analysis for those.
- Broad list calls (`describe-log-groups`, `describe-security-groups` without filters) can return payloads that exceed the Lambda response limit, causing 502 errors.
- Cold starts on the proxy Lambda cause transient 502 errors on the first few calls if the workflow has been idle.

### Potential improvements

- **Give workers filesystem access** so they can read the CSV, update their columns, and write back directly — avoiding the coordinator relay and timeout issues.
- **Process rows individually** rather than the entire CSV in one generation to reduce cognitive load on the model.
- **Use a larger model** (gpt-4o) for the auditor agent specifically, since it handles structured data more reliably.
- **Switch from pipe-delimited CSV to JSON** for the inter-agent data format, which models handle more reliably than positional tabular formats.
