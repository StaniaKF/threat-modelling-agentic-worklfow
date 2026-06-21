import json

import pytest
import typer

import utils.setup_commands as sc


@pytest.fixture(autouse=True)
def no_dotenv(monkeypatch):
    monkeypatch.setattr("utils.setup_commands.load_dotenv", lambda *a, **kw: None)


@pytest.fixture
def all_env_vars(monkeypatch):
    for var in ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]:
        monkeypatch.setenv(var, "test_value")


@pytest.fixture
def valid_inputs_dir(monkeypatch, tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "mermaid.md").write_text("diagram")
    (inputs / "context.md").write_text("context")
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", inputs)
    return inputs


# --- validate_environment ---


def test_validate_environment_succeeds(valid_inputs_dir, all_env_vars):
    sc.validate_environment()


@pytest.mark.parametrize(
    "missing_var", ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]
)
def test_validate_environment_missing_env_var(
    monkeypatch, valid_inputs_dir, missing_var
):
    for var in ["LITELLM_API_BASE_URL", "LITELLM_API_KEY", "AWS_PROFILE"]:
        if var == missing_var:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, "test_value")

    with pytest.raises(typer.Exit) as exc:
        sc.validate_environment()
    assert exc.value.exit_code == 1


def test_validate_environment_missing_inputs_dir(monkeypatch, all_env_vars, tmp_path):
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", tmp_path / "nonexistent")
    with pytest.raises(typer.Exit) as exc:
        sc.validate_environment()
    assert exc.value.exit_code == 1


def test_validate_environment_missing_mermaid(monkeypatch, all_env_vars, tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "context.md").write_text("context")
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", inputs)
    with pytest.raises(typer.Exit) as exc:
        sc.validate_environment()
    assert exc.value.exit_code == 1


def test_validate_environment_missing_context(monkeypatch, all_env_vars, tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "mermaid.md").write_text("diagram")
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", inputs)
    with pytest.raises(typer.Exit) as exc:
        sc.validate_environment()
    assert exc.value.exit_code == 1


# --- clean_outputs ---


def test_clean_outputs_creates_dir_when_missing(monkeypatch, tmp_path):
    outputs = tmp_path / "outputs"
    monkeypatch.setattr("utils.setup_commands.OUTPUTS_DIR", outputs)
    assert not outputs.exists()
    sc.clean_outputs()
    assert outputs.is_dir()


def test_clean_outputs_removes_existing_files(monkeypatch, tmp_path):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    (outputs / "leftover.txt").write_text("old content")
    monkeypatch.setattr("utils.setup_commands.OUTPUTS_DIR", outputs)
    sc.clean_outputs()
    assert outputs.is_dir()
    assert not (outputs / "leftover.txt").exists()


# --- read_input ---


def test_read_input_returns_file_content(monkeypatch, tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "context.md").write_text("hello world")
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", inputs)
    assert sc.read_input("context.md") == "hello world"


def test_read_input_missing_file_returns_empty_string(monkeypatch, tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    monkeypatch.setattr("utils.setup_commands.INPUTS_DIR", inputs)
    assert sc.read_input("nonexistent.md") == ""


# --- create_initial_threats_json ---


def test_create_initial_threats_json_creates_file(monkeypatch, tmp_path):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    threats_path = outputs / "threats.json"
    monkeypatch.setattr("utils.setup_commands.THREATS_JSON_PATH", threats_path)

    sc.create_initial_threats_json("My Service")

    data = json.loads(threats_path.read_text())
    assert data["metadata"]["service_project"] == "My Service"
    assert data["metadata"]["date_of_analysis"] == sc.TODAY
    assert data["threats"] == []


@pytest.mark.parametrize(
    "service_name", ["Auth Service", "Payment API", "Unknown Service"]
)
def test_create_initial_threats_json_service_name(monkeypatch, tmp_path, service_name):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    threats_path = outputs / "threats.json"
    monkeypatch.setattr("utils.setup_commands.THREATS_JSON_PATH", threats_path)

    sc.create_initial_threats_json(service_name)

    data = json.loads(threats_path.read_text())
    assert data["metadata"]["service_project"] == service_name
