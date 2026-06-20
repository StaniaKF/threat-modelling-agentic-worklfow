# Workflow Diagram

```mermaid
flowchart TD
    %% Python orchestrator
    script["main.py\n(Python orchestrator)"]

    %% Input files
    context["inputs/context.md"]
    mermaid["inputs/mermaid.md"]
    cf["inputs/cloud-formation.yaml"]

    %% Shared data file
    threats_json[("outputs/threats.json")]

    %% Agents
    threat_id["Threat Identifier Agent"]
    risk["Risk Assessor Agent"]
    planner["Mitigation Planner Agent"]
    auditor["Mitigation Auditor Agent"]

    %% Validators
    v1{{"validate_after_threat_identifier"}}
    v2{{"validate_after_risk_assessor\n+ compute risk from matrix"}}
    v3{{"validate_after_mitigation_planner"}}
    v4{{"validate_after_mitigation_auditor"}}

    %% Output files
    analysis["outputs/analysis.md"]
    threats_csv["outputs/threats.csv"]

    %% External
    aws[("AWS Account\n(via MCP proxy)")]

    %% Script reads inputs
    context -->|"reads"| script
    mermaid -->|"reads"| script
    cf -->|"reads"| script

    %% Script creates initial file
    script -->|"1. creates initial JSON"| threats_json

    %% Step 2: Threat Identifier + Validation
    script -->|"2. runs with diagram + context"| threat_id
    threat_id -->|"reads/writes"| threats_json
    threat_id -->|"writes"| analysis
    threats_json --> v1
    v1 -->|"✗ retry"| threat_id
    v1 -->|"✓"| script

    %% Step 3: Risk Assessor + Validation
    script -->|"3. runs with context + CloudFormation"| risk
    risk -->|"reads/writes"| threats_json
    threats_json --> v2
    v2 -->|"✗ retry"| risk
    v2 -->|"✓ writes risk field"| script

    %% Step 4: Mitigation Planner + Validation
    script -->|"4. runs"| planner
    planner -->|"reads/writes"| threats_json
    threats_json --> v3
    v3 -->|"✗ retry"| planner
    v3 -->|"✓"| script

    %% Step 5: Mitigation Auditor + Validation
    script -->|"5. runs with context + CF + diagram"| auditor
    auditor -->|"reads/writes"| threats_json
    auditor -->|"queries"| aws
    threats_json --> v4
    v4 -->|"✗ retry"| auditor
    v4 -->|"✓"| script

    %% Step 6: Convert to CSV
    script -->|"6. convert_to_csv()"| threats_json
    threats_json -->|"→"| threats_csv

    %% Styling
    classDef orchestrator fill:#fff9c4,stroke:#f9a825,stroke-width:2px
    classDef agent fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    classDef file fill:#fff3e0,stroke:#f57c00,stroke-width:1.5px
    classDef data fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#c62828,stroke-width:1.5px
    classDef validator fill:#f3e5f5,stroke:#7b1fa2,stroke-width:1.5px

    class script orchestrator
    class threat_id,risk,planner,auditor agent
    class context,mermaid,cf,analysis,threats_csv file
    class threats_json data
    class aws external
    class v1,v2,v3,v4 validator
```

## Key Differences from Project 3

- **No coordinator agent** — Python orchestrates directly (cheaper, faster, no parallel execution bugs)
- **Risk calculated in code** — agent only assesses impact + likelihood; risk is derived from the matrix deterministically
- **Single entry point** — `main.py` is both the CLI and the workflow

## Validation Logic

| Validator | What it checks |
|-----------|---------------|
| `validate_after_threat_identifier` | Non-empty threats array, all 4 fields present, valid STRIDE categories |
| `validate_after_risk_assessor` | Impact/likelihood valid + **computes risk from matrix and writes it** |
| `validate_after_mitigation_planner` | all_possible_mitigations is array of 1-10 strings per threat |
| `validate_after_mitigation_auditor` | in_place + missing = all_possible, remaining_risk valid |

## Agent Responsibilities

| Agent | Input | Adds to threats.json |
|-------|-------|---------------------|
| Threat Identifier | diagram + context | stride_category, element, threat, attack_method |
| Risk Assessor | context + CloudFormation | impact, likelihood |
| Mitigation Planner | (reads threats.json) | all_possible_mitigations |
| Mitigation Auditor | context + CF + diagram + AWS | mitigations_already_in_place, mitigations_missing, ai_proposed_mitigations, remaining_risk |

Note: `risk` is computed by the validator, not the agent.
