# Learnings: LLM Reliability in Agentic Workflows

Accumulated learnings from building an automated threat modelling pipeline across 4 project iterations, each addressing issues discovered in the previous one.

## Project Evolution

| Project | Architecture | Key change |
|---------|-------------|------------|
| 1 | Coordinator + workers, CSV output, no filesystem MCP for workers | Baseline — many issues |
| 2 | Coordinator + workers, CSV output, workers relay through coordinator | Removed custom threat modelling MCP server |
| 3 | Coordinator + workers, JSON output, workers write files directly, validation + retry | Introduced JSON, filesystem MCP for workers, programmatic validation |
| 4 | No coordinator, Python orchestration, structured output for auditor, per-threat processing | Eliminated coordinator, structured output, deterministic post-processing |

---

## Issues Encountered

### 1. CSV Column Misalignment (Projects 1-2)

**Problem:** When agents wrote directly to a pipe-delimited CSV, the model frequently miscounted pipe delimiters — merging columns, dropping them, or shifting content into wrong positions.

**Root cause:** Positional tabular formats are fundamentally difficult for LLMs. Each row had 14 fields with semicolons, numbered lists, and long descriptions. The model confuses structural delimiters with content.

**Resolution:** Switched from CSV to JSON as the inter-agent data format (Project 3). CSV is only generated at the end by a deterministic Python function.

---

### 2. Coordinator Relay Bottleneck (Projects 1-2)

**Problem:** Workers returned their output to the coordinator, which then wrote it to disk. This caused:
- Timeout risk — the auditor must generate all rows in a single LLM response
- Coordinator sometimes forgot to write the file and just presented a summary

**Resolution:** Gave workers direct filesystem MCP access so they read/write `threats.json` themselves (Project 3). Later, removed the coordinator entirely and had Python orchestrate directly (Project 4).

---

### 3. Malformed JSON Output (Project 3)

**Problem:** LLMs (gpt-4o-mini) frequently produce invalid JSON when writing large structured files:
- Extra closing brace `}` at the end
- Missing comma delimiters between objects
- "Extra data" after valid JSON — model appends explanation text after the closing brace
- Trailing commas

**Frequency:** ~30% of mitigation planner and risk assessor runs.

**Root cause:** The model treats file writing as "answering a question" — it generates the JSON, then sometimes adds natural language afterward in the same `write_file` call.

**Resolution:** Programmatic JSON validation after each write + retry with specific error message. The model almost always fixes it on the second attempt.

---

### 4. Output Truncation (Projects 3-4)

**Problem:** When output is large (12+ threats × many fields), the model silently drops items from the end. A file with 12 threats goes in, 4-6 come out.

**Root cause:**
- Model hits output token limits and stops mid-generation
- Failed tool calls consume turns, leaving fewer for the actual write
- The model doesn't realise it's truncating

**Resolution:**
- Pre-count threats before the agent runs, validate count matches after
- Cap mitigations to 10 per threat (reduce output size)
- Process threats one at a time for the auditor (Project 4)
- Block unsupported services so the agent doesn't waste turns

---

### 5. Parallel Tool Calls / Race Conditions (Project 3)

**Problem:** The coordinator called all worker tools simultaneously despite instructions saying "execute in exact order." Workers found `threats.json` empty because the previous agent hadn't finished writing.

**Frequency:** Every run before the fix.

**Root cause:** gpt-4o-mini aggressively parallelises function calls by default. Prompt instructions are insufficient to override this.

**Resolution:** `ModelSettings(parallel_tool_calls=False)` — the SDK-level setting. Prompts alone did not work.

---

### 6. Coordinator Retrying Exhausted Tools (Project 3)

**Problem:** When a tool returned "VALIDATION FAILED after 3 attempts", the coordinator called it again — starting a fresh cycle. The auditor ran 14 times.

**Root cause:** The coordinator is an LLM — it sees "failed" and instinctively retries. It doesn't understand that retries were already exhausted.

**Resolution (Project 3):** Explicit instruction: "If a tool returns 'VALIDATION FAILED after', STOP immediately."

**Better resolution (Project 4):** Removed the coordinator entirely. Python controls the retry logic — no LLM deciding whether to retry.

---

### 7. Excessive Mitigation Generation (Projects 3-4)

**Problem:** The mitigation planner generated 126 mitigations for a single threat. The downstream auditor couldn't sort that many items.

**Root cause:** "Identify ALL possible mitigations" is interpreted literally. The model generates every conceivable control.

**Resolution:** Instructions say "AIM FOR 4-8 PER THREAT. Do NOT list more than 10." Validator enforces the cap.

---

### 8. Risk Matrix Miscalculation (Project 3)

**Problem:** The model occasionally computed wrong risk levels from the matrix (~10% error rate).

**Root cause:** The model does arithmetic/lookup in its head rather than following the table precisely.

**Resolution:** Removed risk calculation from the LLM entirely. The agent only assesses impact and likelihood (qualitative judgement). Risk is computed deterministically in Python. Zero errors since.

---

### 9. Mitigation Sorting / Hallucination (Projects 3-4)

**Problem:** When asked to sort mitigations into "already in place" vs "missing" buckets, the LLM:
- Hallucinated items not in the original list
- Omitted items from both buckets
- Counts never matched (3 in place + 5 missing ≠ 7 total)

**Root cause:** Sorting a fixed list into buckets while maintaining exact text is a mechanical task that LLMs struggle with. They approximate rather than precisely track set membership.

**Resolution (Project 4):** Structured output with a checklist schema — instead of building two arrays, the agent annotates each item with `{mitigation_name, status}`. Python then splits into arrays and auto-corrects any mismatches.

---

### 10. Context Window Overflow (Project 4)

**Problem:** The mitigation auditor hit the 128K token limit on gpt-4o-mini because AWS MCP tool responses accumulated across turns.

**Root cause:** Each AWS API call returns a large JSON blob. After 10-15 tool calls, the conversation history exceeds 128K tokens.

**Resolution:**
- Removed filesystem MCP from the auditor (Python handles file I/O)
- Process one threat at a time (not all 12 in one session)
- Limit max_turns to 35
- Use gpt-4.1-mini (1M context window) for the auditor specifically

---

### 11. MaxTurnsExceeded (Project 4)

**Problem:** Agent hit the turn limit before producing structured output.

**Root cause:** The agent made too many AWS calls (some of which failed/retried) before getting to the output generation step.

**Resolution:** Increased max_turns from 20 to 35, added exception handling so the workflow degrades gracefully instead of crashing, instructed the agent to make max 5-6 calls.

---

### 12. AWS MCP Proxy Limitations (All projects)

**Problem:** Unsupported services (ElastiCache, API Gateway, Config, GuardDuty, SecurityHub, Macie, Inspector) return errors that consume the agent's turn budget.

**Resolution:**
- Explicit blocklist in instructions for unsupported services
- Instructions to use filtered/targeted queries
- Fall back to CloudFormation analysis when AWS calls fail
- Warm-up call (`sts get-caller-identity`) to avoid cold-start 502s

---

## What Works

| Technique | Why it works |
|-----------|-------------|
| **Deterministic post-processing** for computable tasks (risk matrix, CSV generation, mitigation sorting) | LLMs make errors on mechanical tasks; code doesn't |
| **Structured output** (Pydantic models) for constrained responses | API guarantees valid schema; eliminates JSON corruption |
| **Programmatic validation + retry with specific error feedback** | The model can fix its own mistakes when told exactly what's wrong |
| **JSON over CSV** for structured data exchange | Models handle nested key-value structures better than positional formats |
| **Per-item processing** (one threat at a time) for complex tasks | Prevents truncation, keeps context small, easier to validate and retry |
| **Python orchestration** over LLM coordinators | Cheaper, faster, no parallel execution bugs, no infinite retry loops |
| **Capping output size** (max mitigations, max threats) | Prevents context overflow and truncation |
| **SDK-level controls** over prompt instructions | Prompts are suggestions; SDK settings are enforced |
| **Explicit blocklists** for known-failing operations | Prevents the agent from wasting turns on doomed calls |
| **Checklist schema** over "build two arrays" | Cognitively simpler for the model — annotate, don't sort |

## What Doesn't Work

| Approach | Why it fails |
|----------|-------------|
| **Relying on prompt instructions for execution order** | Models parallelise by default regardless of instructions |
| **Asking the model to "validate before writing"** | It claims to validate but still writes garbage ~30% of the time |
| **"Identify ALL possible mitigations"** | Models take this literally and produce unbounded output |
| **Large structured output in a single LLM response** | Token limits + many items = guaranteed truncation |
| **Trusting the model to count or sort precisely** | Models hallucinate counts; always verify in code |
| **LLM coordinators for fixed sequential workflows** | Adds cost, latency, and failure modes for no benefit |
| **Assuming idempotency** on retry | Same input + same model ≈ same output. Change something or give up |
| **Giving an agent a 10K+ token file to "use if needed"** | It reads the whole thing, filling context; pass only relevant excerpts |
| **Small context models (128K) with tool-heavy agents** | AWS responses are huge; 10 calls can fill 128K easily |

---

## Design Principles for Reliable Agentic Workflows

1. **LLMs for judgement, code for mechanics.** Use the LLM for qualitative analysis (is this threat high impact?) and deterministic code for everything computable (risk matrix, counting, sorting, JSON validation).

2. **Validate every LLM output.** Never trust that data produced by an LLM is valid. Parse it. Count its elements. Check its schema. Fix what you can programmatically.

3. **Give specific feedback on retry.** "Your output is wrong" doesn't help. "Threat 3: risk is 'Medium' but matrix says Impact=High + Likelihood=Medium → 'High'" does.

4. **Bound the output space.** Cap arrays, limit item counts, reduce fields per step. Smaller outputs = fewer errors.

5. **Process items individually for complex tasks.** If one item fails, retry just that item — not the entire batch.

6. **Use structured output where possible.** Pydantic models + `output_type` eliminate JSON corruption. Reserve free-form output for creative/analytical tasks.

7. **Python orchestration over LLM coordinators.** For fixed workflows, a for-loop is more reliable than a prompt.

8. **Fail gracefully, not catastrophically.** Catch exceptions, use partial results, fill gaps with safe defaults (e.g., unverified mitigations → "missing").

9. **Use SDK controls, not just prompts.** If something must be sequential, enforce it in code. If context is limited, reduce input programmatically.

10. **Pre-process errors out of the agent's path.** Block unsupported services, filter large files, warm up connections — don't let the agent discover limitations at runtime.
