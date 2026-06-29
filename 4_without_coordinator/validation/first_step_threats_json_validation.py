from enum import StrEnum

import typer

from utils.messages_printing import print_error, print_success
from validation.validators import _load_threats


class WorkflowSteps(StrEnum):
    """Valid sequential blocks of workflow steps."""

    IDENTIFY = "Identify"
    ASSESS = "Assess"
    PLAN = "Plan"
    AUDIT = "Audit"

    IDENTIFY_ASSESS = "Identify-Assess"
    ASSESS_PLAN = "Assess-Plan"
    PLAN_AUDIT = "Plan-Audit"

    IDENTIFY_ASSESS_PLAN = "Identify-Assess-Plan"
    ASSESS_PLAN_AUDIT = "Assess-Plan-Audit"

    ALL = "Identify-Assess-Plan-Audit"


_FIELD_PREREQUISITES_FOR_FIRST_STEP = {
    WorkflowSteps.ASSESS: {"stride_category", "element", "threat", "attack_method"},
    WorkflowSteps.PLAN: {
        "stride_category",
        "element",
        "threat",
        "attack_method",
        "impact",
        "likelihood",
        "risk",
    },
    WorkflowSteps.AUDIT: {
        "stride_category",
        "element",
        "threat",
        "attack_method",
        "impact",
        "likelihood",
        "risk",
        "all_possible_mitigations",
    },
}


def validate_threats_json_for_first_step(first_step: str) -> None:
    """Check that threats.json has the fields required by the first step and none from it or later.

    - Missing required fields → error (earlier steps haven't run)
    - Fields from the first selected step already populated → warning (data may be overwritten)
    """
    if first_step == WorkflowSteps.IDENTIFY:
        return

    data, err = _load_threats()
    if err:
        print_error(f"   ❌  Cannot start at '{first_step}': {err}")
        raise typer.Exit(1)

    threats = data.get("threats", [])
    if not threats:
        print_error(
            f"   ❌  Cannot start at '{first_step}': threats.json has no threats."
        )
        raise typer.Exit(1)

    required_fields_for_first_step = _FIELD_PREREQUISITES_FOR_FIRST_STEP[first_step]

    for i, threat in enumerate(threats):
        present_fields = {k for k, v in threat.items() if v is not None}

        # Check for missing prerequisite fields
        missing_fields = required_fields_for_first_step - present_fields
        if missing_fields:
            print_error(
                f"   ❌  Threat {i} is missing fields needed for '{first_step}': {missing_fields}\n"
                f"        Run earlier steps first.",
            )
            raise typer.Exit(1)

        # Check for any extra fields
        extra_fields = present_fields - required_fields_for_first_step
        if extra_fields:
            print_error(
                f"   ❌  Threat {i} contains extra fields {extra_fields} that should not be present for '{first_step}'.\n"
                f"       Run only the required earlier steps first, or clean outputs and start fresh."
            )
            raise typer.Exit(1)

    print_success(f"   ✓ Prerequisites for '{first_step}' satisfied")
