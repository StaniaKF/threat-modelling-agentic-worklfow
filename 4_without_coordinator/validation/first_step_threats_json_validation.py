from enum import StrEnum

import typer

from validation.validators import _load_threats


class WorkflowSteps(StrEnum):
    """Valid sequential blocks of workflow steps."""

    IDENTIFY = "identify"
    ASSESS = "assess"
    PLAN = "plan"
    AUDIT = "audit"

    IDENTIFY_ASSESS = "identify-assess"
    ASSESS_PLAN = "assess-plan"
    PLAN_AUDIT = "plan-audit"

    IDENTIFY_ASSESS_PLAN = "identify-assess-plan"
    ASSESS_PLAN_AUDIT = "assess-plan-audit"

    ALL = "identify-assess-plan-audit"


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
        typer.echo(f"❌ Cannot start at '{first_step}': {err}", err=True)
        raise typer.Exit(1)

    threats = data.get("threats", [])
    if not threats:
        typer.echo(
            f"❌ Cannot start at '{first_step}': threats.json has no threats.", err=True
        )
        raise typer.Exit(1)

    required_fields_for_first_step = _FIELD_PREREQUISITES_FOR_FIRST_STEP[first_step]

    for i, threat in enumerate(threats):
        present_fields = {k for k, v in threat.items() if v is not None}

        # Check for missing prerequisite fields
        missing_fields = required_fields_for_first_step - present_fields
        if missing_fields:
            typer.echo(
                f"❌ Threat {i} is missing fields needed for '{first_step}': {missing_fields}\n"
                f"   Run earlier steps first.",
                err=True,
            )
            raise typer.Exit(1)

        # Check for any extra fields
        extra_fields = present_fields - required_fields_for_first_step
        if extra_fields:
            typer.echo(
                f"❌ Threat {i} contains extra fields {extra_fields} that should not be present for '{first_step}'.\n"
                f"   Run only the required earlier steps first, or clean outputs and start fresh.",
                err=True,
            )
            raise typer.Exit(1)

    typer.echo(f"   ✓ Prerequisites for '{first_step}' satisfied")
