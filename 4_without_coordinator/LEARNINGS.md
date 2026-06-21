# Learnings: LLM Reliability in Agentic Workflows

## Issues Encountered

### 1. Malformed JSON Output

**Problem:** LLMs (gpt-4o-mini) frequently produce invalid JSON when writing large structured files. Common failure modes:
- Extra closing brace `}` at the end (1 extra byte corrupts the whole file)
- Missing comma delimiters between objects
- "Extra data" after the valid JSON — the model appends explanation text after the closing brace
- Trailing commas (invalid in JSON)

**Frequency:** Observed in ~30% of mitigation planner and risk assessor runs.

**Root cause:** The model treats file writing as "answering a question" — it generates the JSON, then sometimes adds a natural language explanation afterward in the same write call. The MCP filesystem `write_file` tool writes whatever string the model provides, including the trailing text.

**What worked:** Programmatic validation after each write (JSON parse check) + retry with the specific error message. The model almost always fixes it on the second attempt when told "your JSON has extra data at position X."

---

### 2. Output Truncation

**Problem:** When the output is large (12+ threats × many fields), the model silently drops items from the end. A file with 12 threats goes in, 4-6 come out.

**Frequency:** Common with the mitigation auditor (which has the most fields per threat) and when the model runs out of turns due to failed AWS API calls.

**Root cause:** 
- The model hits output token limits and stops mid-generation
- Failed tool calls (AWS errors) consume turns, leaving fewer turns for the actual write
- The model doesn't realise it's truncating — it just stops when it runs out of space

**What worked:**
- Pre-counting threats before the agent runs, then validating the count matches after
- Capping mitigations per threat to 10 (reducing total output size)
- Adding unsupported services to a blocklist so the agent doesn't waste turns on doomed API calls

---

### 3. Parallel Tool Calls (Race Conditions)

**Problem:** The coordinator agent called all worker tools simultaneously despite instructions saying "execute in exact order." Risk assessor and mitigation planner both found `threats.json` empty because the threat identifier hadn't finished writing yet.

**Frequency:** Happened on every run before the fix.

**Root cause:** gpt-4o-mini aggressively parallelises function calls by default. Prompt instructions alone ("do these in order") are insufficient to override this behaviour.

**What worked:** `ModelSettings(parallel_tool_calls=False)` — the SDK-level setting that disables parallel tool calls. This is the only reliable fix; prompt instructions alone did not work.

---

### 4. Coordinator Retrying Exhausted Tools

**Problem:** When a worker tool returned "VALIDATION FAILED after 3 attempts", the coordinator treated this as a normal failure and called the same tool again — starting a fresh 3-attempt cycle. The mitigation auditor ran 14 times.

**Frequency:** Every time a tool exhausted its retries.

**Root cause:** The coordinator is an LLM too — it sees "failed" and its instinct is to retry. It doesn't understand that the validation wrapper already retried.

**What worked:** Explicit instruction: "If a tool returns a message starting with 'VALIDATION FAILED after', STOP immediately and report the failure. Do NOT retry."

---

### 5. Excessive Mitigation Generation

**Problem:** The mitigation planner generated 126 mitigations for a single threat. The downstream auditor then had to sort each one into "in place" or "missing" — impossible in one turn.

**Frequency:** Intermittent. Happened when instructions said "identify ALL possible mitigations."

**Root cause:** "ALL possible" is interpreted literally by the model. It generates an exhaustive list of every conceivable control, no matter how marginal.

**What worked:** Changed instructions to "AIM FOR 4-8 MITIGATIONS PER THREAT. Do NOT list more than 10." Added a validator cap of 10 that triggers a retry if exceeded.

---

### 6. Risk Matrix Miscalculation

**Problem:** The model occasionally computed the wrong risk level from the matrix. E.g., Impact=Medium + Likelihood=Low should be "Low" but the model wrote "Medium."

**Frequency:** ~10% of threats per run.

**Root cause:** The model is doing arithmetic/lookup in its head rather than following the table precisely. Small models make these errors more often.

**What worked:** Removed risk calculation from the LLM entirely. The agent now only assesses impact and likelihood (qualitative judgement — what LLMs are good at). The risk value is computed deterministically in Python using the matrix. Zero errors since this change.

---

### 7. CSV Column Misalignment (Project 2 → Project 3)

**Problem:** In earlier iterations where agents wrote directly to a pipe-delimited CSV, the model frequently miscounted pipe delimiters — merging columns, dropping them, or shifting content.

**Root cause:** Positional tabular formats are fundamentally difficult for LLMs. Each row has 14 fields with semicolons, numbered lists, and long descriptions. The model confuses structural delimiters with content.

**What worked:** Switching from CSV to JSON as the inter-agent data format. The CSV is only generated at the end by a deterministic Python function (`convert_to_csv`). This eliminated all column alignment issues.

---

### 8. AWS MCP Proxy Limitations

**Problem:** Unsupported services (ElastiCache, Config, GuardDuty, SecurityHub, Macie, Inspector) return errors that consume the agent's turn budget. Broad API calls (list all security groups) exceed Lambda payload limits causing 502 errors.

**What worked:**
- Explicit blocklist in the agent instructions for unsupported services
- Instructions to use filtered/targeted queries (e.g., `--group-ids sg-xxx` instead of listing all)
- Instructions to fall back to CloudFormation analysis when AWS API fails
- Warm-up call (`sts get-caller-identity`) before heavy queries to avoid cold-start 502s

---

## General Learnings About LLMs in Agentic Workflows

### What Works

| Technique | Why it works |
|-----------|-------------|
| **Deterministic post-processing** for computable tasks (risk matrix, CSV generation) | LLMs make errors on mechanical tasks; code doesn't |
| **Programmatic validation + retry with error feedback** | The model can fix its own mistakes when told exactly what's wrong |
| **JSON over CSV** for structured data exchange | Models handle nested key-value structures better than positional formats |
| **Capping output size** (max mitigations, max threats) | Prevents context overflow and truncation |
| **SDK-level controls** (`parallel_tool_calls=False`) over prompt instructions | Prompts are suggestions; SDK settings are enforced |
| **Smaller, focused agents** each doing one task | Reduces cognitive load and output size per agent |
| **Explicit blocklists** for known-failing operations | Prevents the agent from wasting turns on doomed calls |
| **Sequential pipeline with shared file** | Each agent can verify it reads what the previous one wrote |

### What Doesn't Work

| Approach | Why it fails |
|----------|-------------|
| **Relying on prompt instructions for execution order** | Models parallelise by default regardless of instructions |
| **Asking the model to "validate before writing"** | It claims to validate but still writes garbage ~30% of the time |
| **"Identify ALL possible mitigations"** | Models take this literally and produce unbounded output |
| **Large CSV generation in a single LLM response** | Token limits + positional tracking = guaranteed corruption |
| **Trusting the model to count** (threats, delimiters, items) | Models hallucinate counts; always verify in code |
| **Assuming idempotency** — calling a tool that failed "one more time" | Same input + same model = same output. Change something or give up. |
| **Broad AWS API calls without filters** | Responses exceed payload limits and cause 502 errors |

### Design Principles for Reliable Agentic Workflows

1. **LLMs for judgement, code for mechanics.** Use the LLM for qualitative analysis (is this threat high impact?) and deterministic code for everything computable (risk matrix lookup, JSON validation, counting).

2. **Validate every write.** Never trust that a file written by an LLM is valid. Parse it. Count its elements. Check its schema.

3. **Give specific feedback on retry.** "Your output is wrong" doesn't help. "Threat 3: risk is 'Medium' but matrix says Impact=High + Likelihood=Medium → 'High'" does.

4. **Bound the output space.** Cap arrays, limit item counts, reduce fields per step. Smaller outputs = fewer errors.

5. **Fail fast and stop.** Don't let the coordinator enter infinite retry loops. After N attempts, report failure clearly.

6. **Use SDK controls, not just prompts.** If something must be sequential, enforce it in code. Prompts are best-effort.

7. **Pre-process errors out of the agent's path.** If an AWS service is unsupported, don't let the agent discover that at runtime — block it upfront.
