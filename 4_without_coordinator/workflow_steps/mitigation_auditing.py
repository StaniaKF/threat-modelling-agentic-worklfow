import json
from enum import StrEnum
from pathlib import Path
from typing import Any
import typer
from agents import Agent, OpenAIChatCompletionsModel, RunConfig, Runner, trace
from openai import AsyncOpenAI
from pydantic import BaseModel
from utils.agent_factory import create_agent
from utils.setup_commands import THREATS_JSON_PATH
from workflow_agent_prompts.mitigation_auditor import (
    INSTRUCTIONS as MITIGATION_AUDITOR_INSTRUCTIONS,
)

AUDITOR_MODEL = "openai/gpt-4.1-mini"


class Status(StrEnum):
    already_in_place = "already_in_place"
    missing = "missing"


class RemainingRisk(StrEnum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"


class MitigationAssessment(BaseModel):
    """Assessment of a single mitigation item."""

    mitigation_name: str
    status: Status
    note: str = ""


class ThreatAuditResult(BaseModel):
    """Structured output from the auditor for a single threat."""

    mitigations_assessment: list[MitigationAssessment]
    ai_proposed_mitigations: list[str]
    remaining_risk: RemainingRisk


async def _execute_threat_audit_attempt(
    agent: Agent,
    run_config: RunConfig,
    audit_input: str,
    all_mitigations: list[str],
    index: int,
) -> ThreatAuditResult | None:
    validation_error: str | None = None
    last_result = None

    for attempt in range(3):
        message = (
            audit_input
            if attempt == 0
            else (
                f"{audit_input}\n\n⚠️ PREVIOUS ATTEMPT FAILED: {validation_error}\n"
                f"Please assess ALL {len(all_mitigations)} mitigations listed above."
            )
        )
        typer.echo(f"    🔄 Attempt {attempt + 1}...")

        try:
            with trace(f"Mitigation Audit - Threat {index}"):
                last_result = await Runner.run(
                    agent, message, run_config=run_config, max_turns=35
                )
        except Exception as e:
            typer.echo(f"    ⚠️  Agent error: {type(e).__name__}: {str(e)[:100]}")
            validation_error = str(e)
            continue

        audit_result = last_result.final_output_as(ThreatAuditResult)
        if audit_result:
            assessed_names = {
                a.mitigation_name for a in audit_result.mitigations_assessment
            }
            missing = [
                mitigation
                for mitigation in all_mitigations
                if mitigation not in assessed_names
            ]

            if not missing and audit_result.remaining_risk in {
                "Low",
                "Medium",
                "High",
                "Critical",
            }:
                return audit_result

            validation_error = f"Missing assessments for: {missing[:3]}..."
            typer.echo(f"    ✗ Incomplete: {len(missing)} mitigations not assessed")
        else:
            validation_error = "Agent did not return structured output"
            typer.echo("    ✗ No structured output returned")

    typer.echo("    ⚠️  Using partial result after retries")
    return last_result.final_output_as(ThreatAuditResult) if last_result else None


def _update_threat_record(
    threat: dict[str, Any], audit_result: ThreatAuditResult, all_mitigations: list[str]
) -> None:
    in_place = []
    missing = []

    for assessment in audit_result.mitigations_assessment:
        name_with_note = (
            f"{assessment.mitigation_name} ({assessment.note})"
            if assessment.note
            else assessment.mitigation_name
        )
        if assessment.status == "already_in_place":
            in_place.append(name_with_note)
        else:
            missing.append(name_with_note)

    assessed_bases = {a.mitigation_name for a in audit_result.mitigations_assessment}
    for mitigation in all_mitigations:
        if mitigation not in assessed_bases:
            missing.append(mitigation)

    threat["mitigations_already_in_place"] = in_place
    threat["mitigations_missing"] = missing
    threat["ai_proposed_mitigations"] = audit_result.ai_proposed_mitigations
    threat["remaining_risk"] = audit_result.remaining_risk


async def run_mitigation_audit(
    client: AsyncOpenAI,
    cloudformation: str,
    aws_mcp: Any,
    threats_json_path: Path = THREATS_JSON_PATH,
) -> None:
    """Step 4: Query live AWS configurations dynamically to audit applied mitigations."""
    typer.echo("\n🔍 Step 4/4: Mitigation Audit")

    auditor_run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=AUDITOR_MODEL, openai_client=client)
    )

    threats_data = json.loads(threats_json_path.read_text(encoding="utf-8"))
    threats = threats_data.get("threats", [])
    total_threats = len(threats)

    for i, threat in enumerate(threats):
        element = threat.get("element", "")
        stride = threat.get("stride_category", "")

        if threat.get("mitigations_already_in_place") is not None:
            typer.echo(
                f"  ⏭️  Threat {i + 1}/{total_threats} ({element}) — already audited, skipping"
            )
            continue

        typer.echo(f"  🔍 Threat {i + 1}/{total_threats}: [{stride}] {element}")

        auditor_agent = create_agent(
            "Mitigation Auditor Agent",
            MITIGATION_AUDITOR_INSTRUCTIONS,
            client,
            [aws_mcp],
            model=AUDITOR_MODEL,
        )
        auditor_agent.output_type = ThreatAuditResult

        audit_input = (
            f"Assess this threat:\n{json.dumps(threat, indent=2)}\n\n"
            f"AWS Account ID: 869935085421, Region: eu-west-1\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}\n\n"
            f"Use the AWS MCP to query live infrastructure for the '{element}' component.\n\n"
            f"IMPORTANT: Keep your AWS queries minimal and targeted. Make at most 5-6 AWS calls total."
        )

        all_mitigations = threat.get("all_possible_mitigations", [])
        audit_result = await _execute_threat_audit_attempt(
            auditor_agent, auditor_run_config, audit_input, all_mitigations, i
        )

        if audit_result:
            _update_threat_record(threat, audit_result, all_mitigations)
            threats_data["threats"] = threats
            threats_json_path.write_text(
                json.dumps(threats_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            typer.echo(
                f"    ✓ {element} — {len(threat['mitigations_already_in_place'])} in place, {len(threat['mitigations_missing'])} missing"
            )
        else:
            typer.echo(f"    ❌ No result for threat {i} — skipping")
