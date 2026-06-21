import json

import pytest

from tests.unit.conftest import full_threat, minimal_threat, write_threats
from validation.validators import (
    validate_after_mitigation_auditor,
    validate_after_mitigation_planner,
    validate_after_risk_assessor,
    validate_after_threat_identifier,
)


# --- validate_after_threat_identifier ---


def test_threat_identifier_file_not_found(patched_threats_json):
    result = validate_after_threat_identifier()
    assert "not found" in result


def test_threat_identifier_invalid_json(patched_threats_json):
    patched_threats_json.write_text("not valid json", encoding="utf-8")
    result = validate_after_threat_identifier()
    assert "not valid JSON" in result


def test_threat_identifier_empty_threats_array(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_threat_identifier()
    assert result is not None
    assert "empty" in result


def test_threat_identifier_valid_data_returns_none(patched_threats_json):
    write_threats(patched_threats_json, [minimal_threat()])
    assert validate_after_threat_identifier() is None


def test_threat_identifier_multiple_valid_threats_returns_none(patched_threats_json):
    threats = [
        minimal_threat(stride_category="Spoofing"),
        minimal_threat(stride_category="Tampering", element="Database"),
        minimal_threat(stride_category="Denial of Service", element="Load Balancer"),
    ]
    write_threats(patched_threats_json, threats)
    assert validate_after_threat_identifier() is None


@pytest.mark.parametrize(
    "missing_field", ["stride_category", "element", "threat", "attack_method"]
)
def test_threat_identifier_missing_required_field(patched_threats_json, missing_field):
    threat = minimal_threat()
    del threat[missing_field]
    write_threats(patched_threats_json, [threat])
    result = validate_after_threat_identifier()
    assert result is not None
    assert missing_field in result


@pytest.mark.parametrize("bad_value", ["", "   ", None])
def test_threat_identifier_empty_or_null_field(patched_threats_json, bad_value):
    threat = minimal_threat(threat=bad_value)
    write_threats(patched_threats_json, [threat])
    result = validate_after_threat_identifier()
    assert result is not None


@pytest.mark.parametrize(
    "category",
    [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ],
)
def test_threat_identifier_valid_stride_categories(patched_threats_json, category):
    write_threats(patched_threats_json, [minimal_threat(stride_category=category)])
    assert validate_after_threat_identifier() is None


def test_threat_identifier_invalid_stride_category(patched_threats_json):
    write_threats(
        patched_threats_json, [minimal_threat(stride_category="NotACategory")]
    )
    result = validate_after_threat_identifier()
    assert result is not None
    assert "stride_category" in result


@pytest.mark.parametrize(
    "unexpected_field",
    ["impact", "likelihood", "risk", "all_possible_mitigations", "remaining_risk"],
)
def test_threat_identifier_rejects_non_null_later_stage_fields(
    patched_threats_json, unexpected_field
):
    threat = minimal_threat(**{unexpected_field: "some value"})
    write_threats(patched_threats_json, [threat])
    result = validate_after_threat_identifier()
    assert result is not None


def test_threat_identifier_allows_null_later_stage_fields(patched_threats_json):
    # Null values for later-stage fields should not cause an error
    threat = minimal_threat(impact=None, likelihood=None, risk=None)
    write_threats(patched_threats_json, [threat])
    assert validate_after_threat_identifier() is None


# --- validate_after_risk_assessor ---


def test_risk_assessor_file_not_found(patched_threats_json):
    result = validate_after_risk_assessor(0)
    assert "not found" in result


def test_risk_assessor_empty_threats_no_prior_count(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_risk_assessor(0)
    assert result is not None
    assert "empty" in result


def test_risk_assessor_expected_count_but_zero_found(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_risk_assessor(3)
    assert result is not None
    assert "0" in result


def test_risk_assessor_count_mismatch(patched_threats_json):
    threats = [minimal_threat(impact="High", likelihood="Medium") for _ in range(2)]
    write_threats(patched_threats_json, threats)
    result = validate_after_risk_assessor(5)
    assert result is not None
    assert "truncation" in result or "duplication" in result


@pytest.mark.parametrize("bad_impact", ["Critical", "VeryHigh", "", None])
def test_risk_assessor_invalid_impact(patched_threats_json, bad_impact):
    threat = minimal_threat(impact=bad_impact, likelihood="Medium")
    write_threats(patched_threats_json, [threat])
    result = validate_after_risk_assessor(0)
    assert result is not None


@pytest.mark.parametrize("bad_likelihood", ["Critical", "VeryHigh", "", None])
def test_risk_assessor_invalid_likelihood(patched_threats_json, bad_likelihood):
    threat = minimal_threat(impact="High", likelihood=bad_likelihood)
    write_threats(patched_threats_json, [threat])
    result = validate_after_risk_assessor(0)
    assert result is not None


@pytest.mark.parametrize(
    "impact,likelihood,expected_risk",
    [
        ("Low", "Low", "Low"),
        ("Low", "Medium", "Low"),
        ("Low", "High", "Medium"),
        ("Medium", "Low", "Low"),
        ("Medium", "Medium", "Medium"),
        ("Medium", "High", "High"),
        ("High", "Low", "Medium"),
        ("High", "Medium", "High"),
        ("High", "High", "Critical"),
    ],
)
def test_risk_assessor_applies_risk_matrix(
    patched_threats_json, impact, likelihood, expected_risk
):
    threat = minimal_threat(impact=impact, likelihood=likelihood)
    write_threats(patched_threats_json, [threat])
    result = validate_after_risk_assessor(0)
    assert result is None
    data = json.loads(patched_threats_json.read_text())
    assert data["threats"][0]["risk"] == expected_risk


def test_risk_assessor_writes_back_all_risks(patched_threats_json):
    threats = [
        minimal_threat(impact="High", likelihood="High"),
        minimal_threat(impact="Low", likelihood="Low", element="DB"),
    ]
    write_threats(patched_threats_json, threats)
    assert validate_after_risk_assessor(0) is None
    data = json.loads(patched_threats_json.read_text())
    assert data["threats"][0]["risk"] == "Critical"
    assert data["threats"][1]["risk"] == "Low"


# --- validate_after_mitigation_planner ---


def test_mitigation_planner_file_not_found(patched_threats_json):
    result = validate_after_mitigation_planner(0)
    assert "not found" in result


def test_mitigation_planner_empty_threats(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_mitigation_planner(0)
    assert result is not None


def test_mitigation_planner_valid_returns_none(patched_threats_json):
    threat = minimal_threat(all_possible_mitigations=["Use MFA", "Rate limiting"])
    write_threats(patched_threats_json, [threat])
    assert validate_after_mitigation_planner(0) is None


def test_mitigation_planner_null_mitigations(patched_threats_json):
    threat = minimal_threat(all_possible_mitigations=None)
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_planner(0)
    assert result is not None
    assert "null" in result


def test_mitigation_planner_not_a_list(patched_threats_json):
    threat = minimal_threat(all_possible_mitigations="not a list")
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_planner(0)
    assert result is not None
    assert "not an array" in result


def test_mitigation_planner_empty_list(patched_threats_json):
    threat = minimal_threat(all_possible_mitigations=[])
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_planner(0)
    assert result is not None
    assert "empty" in result


def test_mitigation_planner_too_many_mitigations(patched_threats_json):
    threat = minimal_threat(
        all_possible_mitigations=[f"control {i}" for i in range(11)]
    )
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_planner(0)
    assert result is not None
    assert "max 10" in result


@pytest.mark.parametrize("bad_item", ["", "   ", None, 42])
def test_mitigation_planner_non_string_item(patched_threats_json, bad_item):
    threat = minimal_threat(all_possible_mitigations=["valid control", bad_item])
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_planner(0)
    assert result is not None


def test_mitigation_planner_expected_count_but_no_threats_found(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_mitigation_planner(3)
    assert result is not None
    assert "0" in result


def test_mitigation_planner_count_mismatch_raises_error(patched_threats_json):
    threats = [minimal_threat(all_possible_mitigations=["ctrl 1"]) for _ in range(2)]
    write_threats(patched_threats_json, threats)
    result = validate_after_mitigation_planner(5)
    assert result is not None


# --- validate_after_mitigation_auditor ---


def test_mitigation_auditor_file_not_found(patched_threats_json):
    result = validate_after_mitigation_auditor(0)
    assert "not found" in result


def test_mitigation_auditor_empty_threats(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_mitigation_auditor(0)
    assert result is not None


def test_mitigation_auditor_valid_returns_none(patched_threats_json):
    write_threats(patched_threats_json, [full_threat()])
    assert validate_after_mitigation_auditor(0) is None


@pytest.mark.parametrize(
    "null_field",
    ["mitigations_already_in_place", "mitigations_missing", "ai_proposed_mitigations"],
)
def test_mitigation_auditor_null_field(patched_threats_json, null_field):
    threat = full_threat(**{null_field: None})
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_auditor(0)
    assert result is not None
    assert "null" in result


@pytest.mark.parametrize(
    "non_list_field",
    ["mitigations_already_in_place", "mitigations_missing", "ai_proposed_mitigations"],
)
def test_mitigation_auditor_non_list_field(patched_threats_json, non_list_field):
    threat = full_threat(**{non_list_field: "not a list"})
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_auditor(0)
    assert result is not None
    assert "not an array" in result


def test_mitigation_auditor_count_mismatch(patched_threats_json):
    # in_place(1) + missing(1) = 2, but all_possible_mitigations has 3
    threat = full_threat(
        all_possible_mitigations=["A", "B", "C"],
        mitigations_already_in_place=["A"],
        mitigations_missing=["B"],
    )
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_auditor(0)
    assert result is not None
    assert "all_possible_mitigations" in result


@pytest.mark.parametrize("bad_remaining", ["None", "Unknown", "", "low", None])
def test_mitigation_auditor_invalid_remaining_risk(patched_threats_json, bad_remaining):
    threat = full_threat(remaining_risk=bad_remaining)
    write_threats(patched_threats_json, [threat])
    result = validate_after_mitigation_auditor(0)
    assert result is not None


@pytest.mark.parametrize("valid_remaining", ["Low", "Medium", "High", "Critical"])
def test_mitigation_auditor_valid_remaining_risk_values(
    patched_threats_json, valid_remaining
):
    threat = full_threat(remaining_risk=valid_remaining)
    write_threats(patched_threats_json, [threat])
    assert validate_after_mitigation_auditor(0) is None


def test_mitigation_auditor_expected_count_but_no_threats_found(patched_threats_json):
    write_threats(patched_threats_json, [])
    result = validate_after_mitigation_auditor(3)
    assert result is not None
    assert "0" in result


def test_mitigation_auditor_count_mismatch_expected_vs_actual(patched_threats_json):
    threats = [full_threat() for _ in range(2)]
    write_threats(patched_threats_json, threats)
    result = validate_after_mitigation_auditor(5)
    assert result is not None
