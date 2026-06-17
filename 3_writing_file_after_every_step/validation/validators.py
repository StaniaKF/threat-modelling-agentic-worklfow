"""
Programmatic validators for each agent step.

Each validator reads threats.json AFTER the agent has written it and returns:
- None if the output is valid
- A string describing all validation errors if invalid

The error string is fed back to the agent on retry so it knows exactly what to fix.
"""

import json
from pathlib import Path

THREATS_JSON = Path(__file__).resolve().parent.parent / "outputs" / "threats.json"

# Risk matrix from the Risk Assessor agent instructions.
# Key: (impact, likelihood) -> expected risk
RISK_MATRIX: dict[tuple[str, str], str] = {
    ("Low", "Low"): "Low",
    ("Low", "Medium"): "Low",
    ("Low", "High"): "Medium",
    ("Medium", "Low"): "Low",
    ("Medium", "Medium"): "Medium",
    ("Medium", "High"): "High",
    ("High", "Low"): "Medium",
    ("High", "Medium"): "High",
    ("High", "High"): "Critical",
}


def _load_threats() -> tuple[dict | None, str | None]:
    """Load and parse threats.json. Returns (data, error)."""
    try:
        data = json.loads(THREATS_JSON.read_text(encoding="utf-8"))
        return data, None
    except FileNotFoundError:
        return None, "threats.json not found"
    except json.JSONDecodeError as e:
        return None, f"threats.json is not valid JSON: {e}"


def validate_after_threat_identifier() -> str | None:
    """Validate threats.json after the Threat Identifier agent has run."""
    data, err = _load_threats()
    if err:
        return err

    threats = data.get("threats", [])
    if not threats:
        return "threats array is empty — no threats were identified"

    errors: list[str] = []
    required_fields = {"stride_category", "element", "threat", "attack_method"}
    valid_categories = {
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    }

    for i, t in enumerate(threats):
        # Check required fields exist and are non-empty strings
        missing = required_fields - set(t.keys())
        if missing:
            errors.append(f"Threat {i}: missing fields {missing}")
            continue

        for field in required_fields:
            val = t.get(field)
            if not isinstance(val, str) or val.strip() == "":
                errors.append(f"Threat {i}: field '{field}' must be a non-empty string, got: {repr(val)}")

        # Validate STRIDE category
        if t.get("stride_category") not in valid_categories:
            errors.append(
                f"Threat {i}: stride_category '{t.get('stride_category')}' "
                f"is not a valid STRIDE category"
            )

        # Should NOT have fields from later stages
        unexpected = {"impact", "likelihood", "risk", "all_possible_mitigations",
                      "mitigations_already_in_place", "mitigations_missing",
                      "ai_proposed_mitigations", "remaining_risk"}
        found_unexpected = unexpected & set(t.keys())
        # Allow null values for fields that may be pre-populated as null
        actual_unexpected = {f for f in found_unexpected if t.get(f) is not None}
        if actual_unexpected:
            errors.append(f"Threat {i}: has unexpected non-null fields {actual_unexpected}")

    return "\n".join(errors) if errors else None


def validate_after_risk_assessor(expected_threat_count: int) -> str | None:
    """Validate threats.json after the Risk Assessor agent has run."""
    data, err = _load_threats()
    if err:
        return err

    threats = data.get("threats", [])

    # If the pre-state had threats but now there are none, something went wrong
    if expected_threat_count > 0 and len(threats) == 0:
        return (
            f"Expected {expected_threat_count} threats but found 0 — "
            f"the agent may not have written the file"
        )

    # If the pre-state had threats, the count must match
    if expected_threat_count > 0 and len(threats) != expected_threat_count:
        return (
            f"Expected {expected_threat_count} threats, got {len(threats)} "
            f"(truncation or duplication detected)"
        )

    # If there are no threats at all, the agent had nothing to work with — that's a
    # workflow ordering error, not a validation error per se, but we should flag it
    if len(threats) == 0:
        return "threats array is empty — risk assessment requires threats to be identified first"

    errors: list[str] = []
    valid_levels = {"Low", "Medium", "High"}
    valid_risk = {"Low", "Medium", "High", "Critical"}

    for i, t in enumerate(threats):
        impact = t.get("impact")
        likelihood = t.get("likelihood")
        risk = t.get("risk")

        # Check that the fields were actually added (not null/missing)
        if impact is None:
            errors.append(f"Threat {i} ({t.get('element')}): impact is null — agent did not assess this threat")
            continue
        if likelihood is None:
            errors.append(f"Threat {i} ({t.get('element')}): likelihood is null — agent did not assess this threat")
            continue
        if risk is None:
            errors.append(f"Threat {i} ({t.get('element')}): risk is null — agent did not assess this threat")
            continue

        if impact not in valid_levels:
            errors.append(f"Threat {i} ({t.get('element')}): impact '{impact}' not in {valid_levels}")
            continue
        if likelihood not in valid_levels:
            errors.append(f"Threat {i} ({t.get('element')}): likelihood '{likelihood}' not in {valid_levels}")
            continue
        if risk not in valid_risk:
            errors.append(f"Threat {i} ({t.get('element')}): risk '{risk}' not in {valid_risk}")
            continue

        # Validate risk matches the matrix
        expected_risk = RISK_MATRIX[(impact, likelihood)]
        if risk != expected_risk:
            errors.append(
                f"Threat {i} ({t.get('element')}): risk is '{risk}' but matrix says "
                f"Impact={impact} + Likelihood={likelihood} → '{expected_risk}'"
            )

    return "\n".join(errors) if errors else None


def validate_after_mitigation_planner(expected_threat_count: int) -> str | None:
    """Validate threats.json after the Mitigation Planner agent has run."""
    data, err = _load_threats()
    if err:
        return err

    threats = data.get("threats", [])

    # Check the agent actually processed threats
    if expected_threat_count > 0 and len(threats) == 0:
        return (
            f"Expected {expected_threat_count} threats but found 0 — "
            f"the agent may not have written the file"
        )

    if expected_threat_count > 0 and len(threats) != expected_threat_count:
        return (
            f"Expected {expected_threat_count} threats, got {len(threats)} "
            f"(truncation or duplication detected)"
        )

    if len(threats) == 0:
        return "threats array is empty — mitigation planning requires threats to be identified first"

    errors: list[str] = []
    for i, t in enumerate(threats):
        mitigations = t.get("all_possible_mitigations")
        if mitigations is None:
            errors.append(
                f"Threat {i} ({t.get('element')}): all_possible_mitigations is null — "
                f"agent did not process this threat"
            )
            continue
        if not isinstance(mitigations, list):
            errors.append(
                f"Threat {i} ({t.get('element')}): all_possible_mitigations is not an array "
                f"(got {type(mitigations).__name__})"
            )
            continue
        if len(mitigations) == 0:
            errors.append(f"Threat {i} ({t.get('element')}): all_possible_mitigations is empty")
            continue
        # Check all items are non-empty strings
        for j, m in enumerate(mitigations):
            if not isinstance(m, str) or m.strip() == "":
                errors.append(
                    f"Threat {i} ({t.get('element')}): all_possible_mitigations[{j}] "
                    f"is not a non-empty string"
                )

    return "\n".join(errors) if errors else None


def validate_after_mitigation_auditor(expected_threat_count: int) -> str | None:
    """Validate threats.json after the Mitigation Auditor agent has run."""
    data, err = _load_threats()
    if err:
        return err

    threats = data.get("threats", [])

    if expected_threat_count > 0 and len(threats) == 0:
        return (
            f"Expected {expected_threat_count} threats but found 0 — "
            f"the agent may not have written the file"
        )

    if expected_threat_count > 0 and len(threats) != expected_threat_count:
        return (
            f"Expected {expected_threat_count} threats, got {len(threats)} "
            f"(truncation or duplication detected)"
        )

    if len(threats) == 0:
        return "threats array is empty — mitigation audit requires threats to be identified first"

    errors: list[str] = []
    valid_remaining_risk = {"Low", "Medium", "High", "Critical"}

    for i, t in enumerate(threats):
        element = t.get("element", f"index {i}")
        in_place = t.get("mitigations_already_in_place")
        missing = t.get("mitigations_missing")
        proposed = t.get("ai_proposed_mitigations")
        remaining = t.get("remaining_risk")
        all_mits = t.get("all_possible_mitigations", [])

        # Check that fields were actually added (not null)
        if in_place is None:
            errors.append(f"Threat {i} ({element}): mitigations_already_in_place is null — agent did not process this threat")
            continue
        if missing is None:
            errors.append(f"Threat {i} ({element}): mitigations_missing is null — agent did not process this threat")
            continue
        if proposed is None:
            errors.append(f"Threat {i} ({element}): ai_proposed_mitigations is null — agent did not process this threat")
            continue

        # Type checks
        if not isinstance(in_place, list):
            errors.append(f"Threat {i} ({element}): mitigations_already_in_place is not an array")
            continue
        if not isinstance(missing, list):
            errors.append(f"Threat {i} ({element}): mitigations_missing is not an array")
            continue
        if not isinstance(proposed, list):
            errors.append(f"Threat {i} ({element}): ai_proposed_mitigations is not an array")
            continue

        # Count check: in_place + missing must equal all_possible_mitigations
        total_sorted = len(in_place) + len(missing)
        if total_sorted != len(all_mits):
            errors.append(
                f"Threat {i} ({element}): mitigations_already_in_place({len(in_place)}) + "
                f"mitigations_missing({len(missing)}) = {total_sorted}, "
                f"but all_possible_mitigations has {len(all_mits)} items"
            )

        # Remaining risk validation
        if remaining not in valid_remaining_risk:
            errors.append(
                f"Threat {i} ({element}): remaining_risk '{remaining}' "
                f"not in {valid_remaining_risk}"
            )

    return "\n".join(errors) if errors else None
