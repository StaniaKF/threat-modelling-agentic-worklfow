import json

import pytest


def minimal_threat(**overrides):
    """Returns a minimal valid threat dict (post threat-identifier stage)."""
    t = {
        "stride_category": "Spoofing",
        "element": "API Gateway",
        "threat": "Attacker impersonates a valid user",
        "attack_method": "Credential stuffing",
    }
    t.update(overrides)
    return t


def full_threat(**overrides):
    """Returns a fully populated threat dict (post all stages)."""
    t = {
        "stride_category": "Spoofing",
        "element": "API Gateway",
        "threat": "Attacker impersonates a valid user",
        "attack_method": "Credential stuffing",
        "impact": "High",
        "likelihood": "Medium",
        "risk": "High",
        "all_possible_mitigations": ["Use MFA", "Rate limiting"],
        "mitigations_already_in_place": ["Use MFA"],
        "mitigations_missing": ["Rate limiting"],
        "ai_proposed_mitigations": ["Implement OAuth2"],
        "remaining_risk": "Medium",
    }
    t.update(overrides)
    return t


@pytest.fixture
def patched_threats_json(monkeypatch, tmp_path):
    """Patch validation.validators.THREATS_JSON to a writable tmp_path location."""
    path = tmp_path / "threats.json"
    monkeypatch.setattr("validation.validators.THREATS_JSON", path)
    return path


def write_threats(path, threats, metadata=None):
    """Write a threats.json file to the given path."""
    data = {
        "metadata": metadata
        or {"date_of_analysis": "2024-01-01", "service_project": "Test"},
        "threats": threats,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return data
