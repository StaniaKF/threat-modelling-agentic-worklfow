"""
Unit tests for _validate_threats_json_for_first_step.

Tests the prerequisite validation logic against threats.json in all states:
- After identify (has stride_category, element, threat, attack_method)
- After assess (adds impact, likelihood, risk)
- After plan (adds all_possible_mitigations)
- After audit (adds mitigations_already_in_place, mitigations_missing, ai_proposed_mitigations, remaining_risk)
"""

import pytest
from typer import Exit as TyperExit

from validation.first_step_threats_json_validation import (
    _validate_threats_json_for_first_step,
)
from tests.unit.conftest import write_threats


# --- Threat fixtures at each pipeline stage ---


def _threat_after_identify():
    """Threat object as it exists after the identify step."""
    return {
        "stride_category": "Spoofing",
        "element": "API Gateway",
        "threat": "Attacker impersonates a valid user",
        "attack_method": "Credential stuffing",
    }


def _threat_after_assess():
    """Threat object as it exists after the assess step."""
    return {
        **_threat_after_identify(),
        "impact": "High",
        "likelihood": "Medium",
        "risk": "High",
    }


def _threat_after_plan():
    """Threat object as it exists after the plan step."""
    return {
        **_threat_after_assess(),
        "all_possible_mitigations": ["Use MFA", "Rate limiting"],
    }


def _threat_after_audit():
    """Threat object as it exists after the audit step."""
    return {
        **_threat_after_plan(),
        "mitigations_already_in_place": ["Use MFA"],
        "mitigations_missing": ["Rate limiting"],
        "ai_proposed_mitigations": ["Implement OAuth2"],
        "remaining_risk": "Medium",
    }


# --- first_step = "identify" (always passes, no-op) ---


def test_identify_always_passes_no_file_needed(patched_threats_json):
    """identify is the first step — no prerequisites, no file read."""
    _validate_threats_json_for_first_step("identify")


# --- first_step = "assess" ---


def test_assess_passes_with_correct_prerequisites(patched_threats_json):
    """After identify, threats.json has exactly the fields assess needs."""
    write_threats(patched_threats_json, [_threat_after_identify()])
    _validate_threats_json_for_first_step("assess")


def test_assess_fails_when_file_missing(patched_threats_json, capsys):
    """No threats.json at all."""
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "Cannot start at 'assess'" in captured.err
    assert "threats.json not found" in captured.err


def test_assess_fails_when_threats_empty(patched_threats_json, capsys):
    """threats.json exists but has no threats."""
    write_threats(patched_threats_json, [])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "no threats" in captured.err


def test_assess_fails_when_missing_required_field(patched_threats_json, capsys):
    """Missing stride_category — identify hasn't fully run."""
    threat = _threat_after_identify()
    del threat["stride_category"]
    write_threats(patched_threats_json, [threat])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "missing" in captured.err.lower()
    assert "stride_category" in captured.err


def test_assess_fails_when_required_field_is_null(patched_threats_json, capsys):
    """Field exists but is None — treated as missing."""
    threat = _threat_after_identify()
    threat["element"] = None
    write_threats(patched_threats_json, [threat])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "element" in captured.err


def test_assess_fails_when_extra_fields_present(patched_threats_json, capsys):
    """File already has impact/likelihood/risk — assess was already run."""
    write_threats(patched_threats_json, [_threat_after_assess()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "extra fields" in captured.err


def test_assess_fails_when_all_steps_already_run(patched_threats_json, capsys):
    """File has all fields — full pipeline was already run."""
    write_threats(patched_threats_json, [_threat_after_audit()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "extra fields" in captured.err


# --- first_step = "plan" ---


def test_plan_passes_with_correct_prerequisites(patched_threats_json):
    """After assess, threats.json has exactly the fields plan needs."""
    write_threats(patched_threats_json, [_threat_after_assess()])
    _validate_threats_json_for_first_step("plan")


def test_plan_fails_when_file_missing(patched_threats_json, capsys):
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "Cannot start at 'plan'" in captured.err


def test_plan_fails_when_threats_empty(patched_threats_json, capsys):
    write_threats(patched_threats_json, [])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "no threats" in captured.err


def test_plan_fails_when_only_identify_has_run(patched_threats_json, capsys):
    """Missing impact, likelihood, risk — assess hasn't run."""
    write_threats(patched_threats_json, [_threat_after_identify()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "missing" in captured.err.lower()


def test_plan_fails_when_risk_is_null(patched_threats_json, capsys):
    """risk field exists but is None."""
    threat = _threat_after_assess()
    threat["risk"] = None
    write_threats(patched_threats_json, [threat])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "risk" in captured.err


def test_plan_fails_when_extra_fields_present(patched_threats_json, capsys):
    """File already has all_possible_mitigations — plan was already run."""
    write_threats(patched_threats_json, [_threat_after_plan()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "extra fields" in captured.err


def test_plan_fails_when_all_steps_already_run(patched_threats_json, capsys):
    write_threats(patched_threats_json, [_threat_after_audit()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("plan")
    captured = capsys.readouterr()
    assert "extra fields" in captured.err


# --- first_step = "audit" ---


def test_audit_passes_with_correct_prerequisites(patched_threats_json):
    """After plan, threats.json has exactly the fields audit needs."""
    write_threats(patched_threats_json, [_threat_after_plan()])
    _validate_threats_json_for_first_step("audit")


def test_audit_fails_when_file_missing(patched_threats_json, capsys):
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "Cannot start at 'audit'" in captured.err


def test_audit_fails_when_threats_empty(patched_threats_json, capsys):
    write_threats(patched_threats_json, [])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "no threats" in captured.err


def test_audit_fails_when_only_identify_has_run(patched_threats_json, capsys):
    """Missing impact, likelihood, risk, all_possible_mitigations."""
    write_threats(patched_threats_json, [_threat_after_identify()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "missing" in captured.err.lower()


def test_audit_fails_when_only_assess_has_run(patched_threats_json, capsys):
    """Missing all_possible_mitigations — plan hasn't run."""
    write_threats(patched_threats_json, [_threat_after_assess()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "missing" in captured.err.lower()


def test_audit_fails_when_all_possible_mitigations_is_null(
    patched_threats_json, capsys
):
    threat = _threat_after_plan()
    threat["all_possible_mitigations"] = None
    write_threats(patched_threats_json, [threat])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "all_possible_mitigations" in captured.err


def test_audit_fails_when_extra_fields_present(patched_threats_json, capsys):
    """File already has audit output — audit was already run."""
    write_threats(patched_threats_json, [_threat_after_audit()])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("audit")
    captured = capsys.readouterr()
    assert "extra fields" in captured.err


# --- Multiple threats ---


def test_multiple_threats_fails_on_second_missing_fields(patched_threats_json, capsys):
    """First threat is valid but second is missing a required field."""
    good = _threat_after_identify()
    bad = _threat_after_identify()
    del bad["attack_method"]
    write_threats(patched_threats_json, [good, bad])
    with pytest.raises(TyperExit):
        _validate_threats_json_for_first_step("assess")
    captured = capsys.readouterr()
    assert "Threat 1" in captured.err
    assert "attack_method" in captured.err


def test_multiple_threats_passes_when_all_have_prerequisites(patched_threats_json):
    threats = [_threat_after_assess() for _ in range(5)]
    write_threats(patched_threats_json, threats)
    _validate_threats_json_for_first_step("plan")
