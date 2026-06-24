# Threat Modelling Agentic Workflow

An iterative exploration of agentic workflow designs for automated STRIDE-based threat modelling on AWS infrastructure. Each project in this repo is a working pipeline that takes the same inputs (architecture diagram, business context, CloudFormation definitions) and produces the same output (a threat model CSV), but is built with a different orchestration approach.

The four agents are the same across all projects:
- **Threat Identifier** — identifies threats using STRIDE methodology
- **Risk Assessor** — evaluates impact and likelihood per threat
- **Mitigation Planner** — proposes security controls per threat
- **Mitigation Auditor** — queries live AWS infrastructure to check which controls are already in place

The projects differ in how those agents are orchestrated, how they share data, and how errors are handled.

---

## Projects

### [1 — With Threat Modelling MCP Server](./1_with-threat-modelling-mcp-server)

**Orchestration:** LLM coordinator agent  
**Data sharing:** Workers return output as text to the coordinator, which writes the CSV  
**Validation:** None

The first iteration. A coordinator LLM agent calls each worker agent as a tool in sequence. Workers have access to two MCP servers: a custom Threat Modelling MCP (provides STRIDE guidance) and the AWS MCP (queries live infrastructure).

**Problems discovered:** Workers relay their full output back through the coordinator, which then writes it to a pipe-delimited CSV. This causes column misalignment (the model miscounts pipe delimiters in wide rows), timeout risk (the auditor must generate all rows in one LLM response), and occasional coordinator amnesia (skips the file write after the last step).

---

### [2 — Without Threat Modelling MCP Server](./2_without-threat-modelling-mcp-server)

**Orchestration:** LLM coordinator agent  
**Data sharing:** Workers return output as text to the coordinator, which writes the CSV  
**Validation:** None

Same coordinator architecture as project 1 but drops the Threat Modelling MCP server — STRIDE guidance is baked into the worker prompts instead. This simplifies the setup but inherits all the same relay and CSV reliability problems.

---

### [3 — Writing File After Every Step](./3_writing_file_after_every_step)

**Orchestration:** LLM coordinator agent  
**Data sharing:** Workers write `threats.json` directly via the filesystem MCP server  
**Validation:** Programmatic Python validators with retry (up to 2 retries per step)

Addresses the relay bottleneck: workers now have filesystem MCP access and write `threats.json` directly after each step instead of passing their output back through the coordinator. Switches from CSV to JSON as the shared intermediate format (models handle JSON far more reliably than positional tabular data). Adds programmatic validation after each step — if a validator fails, the agent is re-run with the specific errors as feedback.

The coordinator is still an LLM, meaning there are still unnecessary token spend and latency for decisions that aren't really decisions.

---

### [4 — Without Coordinator](./4_without_coordinator)

**Orchestration:** Python script  
**Data sharing:** Workers write `threats.json` directly via the filesystem MCP server  
**Validation:** Programmatic Python validators with retry (up to 2 retries per step)

Removes the LLM coordinator entirely. Since the workflow is linear and fixed, a Python script calling each agent in order does the same job — cheaper (no coordinator LLM calls), faster (no extra round-trips), and more reliable (the orchestration logic is explicit Python, not hidden in a prompt). The four-step pipeline and validation system are identical to project 3.
