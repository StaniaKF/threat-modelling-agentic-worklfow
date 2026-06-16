import json
import os

from agents import function_tool

THREATS_JSON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "threats.json"
)
THREATS_CSV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "threats.csv"
)


@function_tool
def convert_to_csv() -> str:
    """Read threats.json and convert it to a pipe-delimited threats.csv file.

    Returns a confirmation message on success or an error message on failure.
    """
    try:
        with open(THREATS_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return "Error: threats.json not found."
    except json.JSONDecodeError as e:
        return f"Error: threats.json is not valid JSON: {e}"

    metadata = data.get("metadata", {})
    date_of_analysis = metadata.get("date_of_analysis", "")
    service_project = metadata.get("service_project", "")
    threats = data.get("threats", [])

    header = (
        "Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|"
        "Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|"
        "Mitigations Already in Place|Mitigations Missing|"
        "AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk"
    )

    def format_field(value):
        """Join arrays with '; ' or return empty string for null/missing."""
        if value is None:
            return ""
        if isinstance(value, list):
            return "; ".join(str(item) for item in value)
        return str(value)

    rows = [header]

    for threat in threats:
        row = "|".join(
            [
                date_of_analysis,
                service_project,
                format_field(threat.get("stride_category")),
                format_field(threat.get("element")),
                format_field(threat.get("threat")),
                format_field(threat.get("impact")),
                format_field(threat.get("likelihood")),
                format_field(threat.get("risk")),
                format_field(threat.get("attack_method")),
                format_field(threat.get("all_possible_mitigations")),
                format_field(threat.get("mitigations_already_in_place")),
                format_field(threat.get("mitigations_missing")),
                format_field(threat.get("ai_proposed_mitigations")),
                format_field(threat.get("remaining_risk")),
            ]
        )
        rows.append(row)

    csv_content = "\n".join(rows) + "\n"

    with open(THREATS_CSV_PATH, "w", encoding="utf-8") as f:
        f.write(csv_content)

    return f"Successfully converted {len(threats)} threats from threats.json to threats.csv (pipe-delimited)."
