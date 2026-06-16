# Workflow Diagram

```mermaid
flowchart TD
    %% Input files
    context["context.md"]
    mermaid["mermaid.md"]
    cf["cloud-formation.yaml"]

    %% Shared data file
    threats_json[("threats.json")]

    %% Agents
    coordinator["Coordinator Agent"]
    threat_id["Threat Identifier Agent"]
    risk["Risk Assessor Agent"]
    planner["Mitigation Planner Agent"]
    auditor["Mitigation Auditor Agent"]

    %% Output files
    analysis["analysis.md"]
    threats_csv["threats.csv"]

    %% External
    aws[("AWS Account\n(via MCP proxy)")]

    %% Step 1-3: Coordinator reads input files
    context -->|"reads"| coordinator
    mermaid -->|"reads"| coordinator
    cf -->|"reads"| coordinator

    %% Step 4: Coordinator creates initial threats.json
    coordinator -->|"1. creates initial JSON with metadata"| threats_json

    %% Step 5: Threat Identifier
    coordinator -->|"2. calls with diagram and context"| threat_id
    threat_id -->|"reads"| threats_json
    threat_id -->|"writes threats array"| threats_json
    threat_id -->|"writes"| analysis

    %% Step 6: Risk Assessor
    coordinator -->|"3. calls with context and CloudFormation"| risk
    risk -->|"reads"| threats_json
    risk -->|"adds impact and likelihood and risk"| threats_json

    %% Step 7: Mitigation Planner
    coordinator -->|"4. calls"| planner
    planner -->|"reads"| threats_json
    planner -->|"adds all_possible_mitigations"| threats_json

    %% Step 8: Mitigation Auditor
    coordinator -->|"5. calls with context and CloudFormation and diagram"| auditor
    auditor -->|"reads"| threats_json
    auditor -->|"queries live resources"| aws
    auditor -->|"adds mitigations in place and missing and proposed and remaining risk"| threats_json

    %% Step 9: Convert to CSV
    coordinator -->|"6. calls convert_to_csv"| threats_json
    threats_json -->|"converted to CSV"| threats_csv

    %% Styling
    classDef agent fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    classDef file fill:#fff3e0,stroke:#f57c00,stroke-width:1.5px
    classDef data fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#c62828,stroke-width:1.5px

    class coordinator,threat_id,risk,planner,auditor agent
    class context,mermaid,cf,analysis,threats_csv file
    class threats_json data
    class aws external
```

## Key Design Principles

1. **JSON as shared data format** — `threats.json` is the single source of truth, passed between agents via filesystem
2. **Workers read/write directly** — each agent has filesystem MCP access to read `threats.json`, add its fields, and write it back
3. **Additive only** — each agent adds new fields without modifying existing ones
4. **No null placeholders** — agents only write the fields they're responsible for
5. **CSV generated at the end** — a Python `convert_to_csv` tool converts the final JSON to pipe-delimited CSV

## Agent Responsibilities

| Agent | Reads | Adds to threats.json |
|-------|-------|---------------------|
| Coordinator | context.md, mermaid.md, cloud-formation.yaml | metadata (date, service name) |
| Threat Identifier | threats.json | stride_category, element, threat, attack_method |
| Risk Assessor | threats.json | impact, likelihood, risk |
| Mitigation Planner | threats.json | all_possible_mitigations (array) |
| Mitigation Auditor | threats.json + AWS | mitigations_already_in_place, mitigations_missing, ai_proposed_mitigations, remaining_risk |

## JSON Format

```json
{
  "metadata": {
    "date_of_analysis": "2026-06-16",
    "service_project": "Smarter Tariff - Small Asset Owner Services"
  },
  "threats": [
    {
      "stride_category": "Spoofing",
      "element": "API Gateway",
      "threat": "[threat in grammar format]",
      "attack_method": "description of how the attack works",
      "impact": "High",
      "likelihood": "Medium",
      "risk": "High",
      "all_possible_mitigations": ["mitigation 1", "mitigation 2"],
      "mitigations_already_in_place": ["mitigation 1"],
      "mitigations_missing": ["mitigation 2"],
      "ai_proposed_mitigations": ["mitigation 2 — reason for priority"],
      "remaining_risk": "Medium"
    }
  ]
}
```
