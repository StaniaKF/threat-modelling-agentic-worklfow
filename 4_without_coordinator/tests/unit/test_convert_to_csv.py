import json

import pytest

from tools.convert_to_csv import convert_to_csv_from_file


@pytest.fixture
def patched_csv_paths(monkeypatch, tmp_path):
    json_path = str(tmp_path / "threats.json")
    csv_path = str(tmp_path / "threats.csv")
    monkeypatch.setattr("tools.convert_to_csv.THREATS_JSON_PATH", json_path)
    monkeypatch.setattr("tools.convert_to_csv.THREATS_CSV_PATH", csv_path)
    return json_path, csv_path


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def read_csv(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# --- error cases ---


def test_convert_file_not_found(patched_csv_paths):
    json_path, _ = patched_csv_paths
    result = convert_to_csv_from_file()
    assert result.startswith("Error")
    assert "not found" in result


def test_convert_invalid_json(patched_csv_paths):
    json_path, _ = patched_csv_paths
    with open(json_path, "w") as f:
        f.write("this is not json {{{")
    result = convert_to_csv_from_file()
    assert result.startswith("Error")
    assert "not valid JSON" in result


# --- success cases ---


def test_convert_empty_threats_writes_header_only(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    write_json(json_path, {"metadata": {}, "threats": []})
    result = convert_to_csv_from_file()
    assert "0 threats" in result
    csv = read_csv(csv_path)
    lines = csv.strip().splitlines()
    assert len(lines) == 1
    assert "STRIDE Category" in lines[0]


def test_convert_header_columns(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    write_json(json_path, {"metadata": {}, "threats": []})
    convert_to_csv_from_file()
    header = read_csv(csv_path).splitlines()[0]
    expected_cols = [
        "Date of analysis",
        "Service/Project Feature",
        "STRIDE Category",
        "Element",
        "Threat",
        "Impact",
        "Likelihood",
        "Risk",
        "Attack Method",
        "All Possible Mitigations",
        "Mitigations Already in Place",
        "Mitigations Missing",
        "AI Proposed High-Risk Missing Mitigations to Implement",
        "Remaining Risk",
    ]
    for col in expected_cols:
        assert col in header


def test_convert_pipe_delimiter(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    write_json(json_path, {"metadata": {}, "threats": []})
    convert_to_csv_from_file()
    header = read_csv(csv_path).splitlines()[0]
    assert "|" in header
    assert "," not in header


def test_convert_single_threat_row(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    threat = {
        "stride_category": "Spoofing",
        "element": "API Gateway",
        "threat": "Fake user",
        "attack_method": "Credential stuffing",
        "impact": "High",
        "likelihood": "Medium",
        "risk": "High",
        "all_possible_mitigations": ["MFA", "Rate limit"],
        "mitigations_already_in_place": ["MFA"],
        "mitigations_missing": ["Rate limit"],
        "ai_proposed_mitigations": ["OAuth2"],
        "remaining_risk": "Medium",
    }
    write_json(
        json_path,
        {
            "metadata": {"date_of_analysis": "2024-01-01", "service_project": "MySvc"},
            "threats": [threat],
        },
    )
    result = convert_to_csv_from_file()
    assert "1 threats" in result

    lines = read_csv(csv_path).strip().splitlines()
    assert len(lines) == 2
    row = lines[1]
    assert "2024-01-01" in row
    assert "MySvc" in row
    assert "Spoofing" in row
    assert "API Gateway" in row
    assert "Credential stuffing" in row
    assert "High" in row


def test_convert_list_fields_joined_with_semicolon(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    threat = {
        "stride_category": "Tampering",
        "element": "DB",
        "threat": "SQL injection",
        "attack_method": "Malicious input",
        "all_possible_mitigations": [
            "Parameterised queries",
            "Input validation",
            "WAF",
        ],
        "mitigations_already_in_place": [],
        "mitigations_missing": ["Parameterised queries", "Input validation", "WAF"],
        "ai_proposed_mitigations": ["Parameterised queries"],
        "remaining_risk": "High",
    }
    write_json(json_path, {"metadata": {}, "threats": [threat]})
    convert_to_csv_from_file()
    row = read_csv(csv_path).strip().splitlines()[1]
    assert "Parameterised queries; Input validation; WAF" in row


@pytest.mark.parametrize(
    "field,value",
    [
        ("impact", None),
        ("likelihood", None),
        ("risk", None),
        ("all_possible_mitigations", None),
        ("remaining_risk", None),
    ],
)
def test_convert_null_fields_produce_empty_string(patched_csv_paths, field, value):
    json_path, csv_path = patched_csv_paths
    threat = {
        "stride_category": "Spoofing",
        "element": "API",
        "threat": "Fake user",
        "attack_method": "Phishing",
        field: value,
    }
    write_json(json_path, {"metadata": {}, "threats": [threat]})
    convert_to_csv_from_file()
    row = read_csv(csv_path).strip().splitlines()[1]
    cols = row.split("|")
    # Ensure at least one column is empty (from the null field)
    assert any(c == "" for c in cols)


def test_convert_returns_success_message_with_count(patched_csv_paths):
    json_path, _ = patched_csv_paths
    threats = [
        {
            "stride_category": "Spoofing",
            "element": f"elem{i}",
            "threat": "t",
            "attack_method": "a",
        }
        for i in range(3)
    ]
    write_json(json_path, {"metadata": {}, "threats": threats})
    result = convert_to_csv_from_file()
    assert "3 threats" in result
    assert "threats.csv" in result


def test_convert_metadata_appears_in_every_row(patched_csv_paths):
    json_path, csv_path = patched_csv_paths
    threats = [
        {
            "stride_category": "Spoofing",
            "element": "A",
            "threat": "t",
            "attack_method": "a",
        },
        {
            "stride_category": "Tampering",
            "element": "B",
            "threat": "t",
            "attack_method": "a",
        },
    ]
    write_json(
        json_path,
        {
            "metadata": {"date_of_analysis": "2024-06-01", "service_project": "SvcX"},
            "threats": threats,
        },
    )
    convert_to_csv_from_file()
    lines = read_csv(csv_path).strip().splitlines()
    for row in lines[1:]:
        assert "2024-06-01" in row
        assert "SvcX" in row
