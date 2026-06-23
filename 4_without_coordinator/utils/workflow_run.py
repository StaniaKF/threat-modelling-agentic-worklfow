import json
import os
from contextlib import AsyncExitStack

import typer
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    RunConfig,
    Runner,
    add_trace_processor,
    trace,
)
from agents.mcp import MCPServerStdio
from openai import AsyncOpenAI

from constants import MODEL, FILESYSTEM_MCP_PARAMS, AWS_MCP_PARAMS
from tools import convert_to_csv_from_file
from utils.agent_run import run_agent_with_validation
from utils.get_trace import FileSpanExporter
from utils.setup_commands import (
    OUTPUTS_DIR,
    THREATS_JSON_PATH,
    read_input,
    create_initial_threats_json,
    TODAY,
)
from validation import (
    validate_after_threat_identifier,
    validate_after_risk_assessor,
    validate_after_mitigation_planner,
)
from worker_agents.mitigation_auditor import (
    INSTRUCTIONS as MITIGATION_AUDITOR_INSTRUCTIONS,
)
from worker_agents.mitigation_planner import (
    INSTRUCTIONS as MITIGATION_PLANNER_INSTRUCTIONS,
)
from worker_agents.risk_assessor import INSTRUCTIONS as RISK_ASSESSOR_INSTRUCTIONS
from worker_agents.threat_identifier import (
    INSTRUCTIONS as THREAT_IDENTIFIER_INSTRUCTIONS,
)


def _extract_service_name(context_text: str) -> str:
    """Safely extracts the service name under 'Project / Service Name' header."""
    lines = [line.strip() for line in context_text.splitlines()]
    for i, line in enumerate(lines):
        if "Project / Service Name" in line:
            for j in range(i + 1, len(lines)):
                if lines[j] and not lines[j].startswith("#"):
                    return lines[j]
    return "Unknown Service"


def _create_agent(
    name: str, instructions: str, client: AsyncOpenAI, mcp_servers: list
) -> Agent:
    """Helper factory to keep agent instantiation clean and uniform."""
    return Agent(
        name=name,
        instructions=instructions,
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client),
        mcp_servers=mcp_servers,
    )


def _create_client() -> AsyncOpenAI:
    """Create an AsyncOpenAI client with environment variables."""
    return AsyncOpenAI(
        base_url=os.getenv("LITELLM_API_BASE_URL"),
        api_key=os.getenv("LITELLM_API_KEY"),
        timeout=300.0,
    )


async def run_workflow() -> None:
    """Execute the full threat modelling workflow."""

    client = _create_client()
    run_config = RunConfig(
        model=OpenAIChatCompletionsModel(model=MODEL, openai_client=client),
    )    
    add_trace_processor(FileSpanExporter(str(OUTPUTS_DIR / "trace_output.json")))

    context = read_input("context.md")
    diagram = read_input("mermaid.md")
    cloudformation = read_input("cloud-formation.yaml")

    service_project = _extract_service_name(context)

    create_initial_threats_json(service_project)

    async with AsyncExitStack() as stack:
        # Start MCP servers
        filesystem_mcp = await stack.enter_async_context(
            MCPServerStdio(FILESYSTEM_MCP_PARAMS)
        )
        aws_mcp = await stack.enter_async_context(
            MCPServerStdio(
                params=AWS_MCP_PARAMS,
                client_session_timeout_seconds=300,
                tool_filter={"blocked_tool_names": ["aws___run_script"]},
            )
        )

        aws_tools = await aws_mcp.list_tools()
        typer.echo(f"   ✓ AWS MCP ready ({len(aws_tools)} tools)")

        # --- Step 1: Threat Identification ---
        typer.echo("\n📋 Step 1/4: Threat Identification")

        threat_identifier_agent = _create_agent(
            "Threat Identifier Agent",
            THREAT_IDENTIFIER_INSTRUCTIONS,
            client,
            [filesystem_mcp],
        )
        threat_identifier_input = (
            f"Today's date: {TODAY}\n\n"
            f"Architecture diagram (mermaid):\n{diagram}\n\n"
            f"Business context:\n{context}"
        )

        with trace("Threat Identification"):
            await run_agent_with_validation(
                threat_identifier_agent,
                threat_identifier_input,
                validate_after_threat_identifier,
                run_config,
                "Threat Identifier",
            )

        # --- Step 2: Risk Assessment ---
        typer.echo("\n📊 Step 2/4: Risk Assessment")
        risk_assessor_agent = _create_agent(
            "Risk Assessor Agent", RISK_ASSESSOR_INSTRUCTIONS, client, [filesystem_mcp]
        )
        risk_input = (
            f"Business context:\n{context}\n\n"
            f"CloudFormation resource definitions:\n{cloudformation}"
        )

        with trace("Risk Assessment"):
            await run_agent_with_validation(
                risk_assessor_agent,
                risk_input,
                validate_after_risk_assessor,
                run_config,
                "Risk Assessor",
            )

        # --- Step 3: Mitigation Planning ---
        typer.echo("\n🛡️ Step 3/4: Mitigation Planning")
        mitigation_planner = _create_agent(
            "Mitigation Planner Agent",
            MITIGATION_PLANNER_INSTRUCTIONS,
            client,
            [filesystem_mcp],
        )

        with trace("Mitigation Planning"):
            await run_agent_with_validation(
                mitigation_planner,
                "",
                validate_after_mitigation_planner,
                run_config,
                "Mitigation Planner",
            )

        # --- Step 4: Mitigation Audit (one threat at a time, structured output) ---
        typer.echo("\n🔍 Step 4/4: Mitigation Audit")

        from worker_agents.mitigation_auditor import ThreatAuditResult

        # Read current threats to iterate
        threats_data = json.loads(THREATS_JSON_PATH.read_text(encoding="utf-8"))
        threats = threats_data.get("threats", [])
        total_threats = len(threats)

        for i, threat in enumerate(threats):
            # Skip if already audited
            if threat.get("mitigations_already_in_place") is not None:
                typer.echo(
                    f"  ⏭️  Threat {i + 1}/{total_threats} ({threat.get('element')}) — already audited, skipping"
                )
                continue

            typer.echo(
                f"  🔍 Threat {i + 1}/{total_threats}: [{threat.get('stride_category')}] {threat.get('element')}"
            )

            mitigation_auditor_agent = _create_agent(
                "Mitigation Auditor Agent",
                MITIGATION_AUDITOR_INSTRUCTIONS,
                client,
                [aws_mcp],
            )
            # Set structured output type
            mitigation_auditor_agent.output_type = ThreatAuditResult

            # Pass only the relevant context — keep input compact
            element = threat.get("element", "")
            audit_input = (
                f"Assess this threat:\n"
                f"{json.dumps(threat, indent=2)}\n\n"
                f"AWS Account ID: 869935085421, Region: eu-west-1\n\n"
                f"CloudFormation resource definitions:\n{cloudformation}\n\n"
                f"Use the AWS MCP to query live infrastructure for the '{element}' component. "
                f"Use FILTERED queries with specific resource IDs. "
                f"If an AWS call fails, use the CloudFormation config above as evidence.\n\n"
                f"IMPORTANT: Keep your AWS queries minimal and targeted. "
                f"Make at most 5-6 AWS calls total."
            )

            # Run with retry (validation checks structured output is complete)
            all_mits = threat.get("all_possible_mitigations", [])

            audit_result = None
            validation_error: str | None = None

            for attempt in range(1 + 2):  # max 2 retries
                message = (
                    audit_input
                    if attempt == 0
                    else (
                        f"{audit_input}\n\n"
                        f"⚠️ PREVIOUS ATTEMPT FAILED: {validation_error}\n"
                        f"Please assess ALL {len(all_mits)} mitigations listed above."
                    )
                )

                typer.echo(f"    🔄 Attempt {attempt + 1}...")

                try:
                    with trace(f"Mitigation Audit - Threat {i}"):
                        result = await Runner.run(
                            mitigation_auditor_agent,
                            message,
                            run_config=run_config,
                            max_turns=35,
                        )
                except Exception as e:
                    typer.echo(
                        f"    ⚠️  Agent error: {type(e).__name__}: {str(e)[:100]}"
                    )
                    validation_error = str(e)
                    continue

                # Extract structured output
                if result.final_output_as(ThreatAuditResult):
                    audit_result = result.final_output_as(ThreatAuditResult)

                    # Validate: did it assess all mitigations?
                    assessed_names = {
                        a.mitigation_name for a in audit_result.mitigations_assessment
                    }
                    missing_from_assessment = [
                        m for m in all_mits if m not in assessed_names
                    ]

                    if not missing_from_assessment and audit_result.remaining_risk in {
                        "Low",
                        "Medium",
                        "High",
                        "Critical",
                    }:
                        break  # Success
                    else:
                        validation_error = (
                            f"Missing assessments for: {missing_from_assessment[:3]}..."
                        )
                        typer.echo(
                            f"    ✗ Incomplete: {len(missing_from_assessment)} mitigations not assessed"
                        )
                else:
                    validation_error = "Agent did not return structured output"
                    typer.echo("    ✗ No structured output returned")
            else:
                # Exhausted retries — use what we have and let post-processing fix it
                typer.echo("    ⚠️  Using partial result after retries")

            # Write results back to threats.json (Python handles the file I/O)
            if audit_result:
                in_place = []
                missing = []
                for assessment in audit_result.mitigations_assessment:
                    name = assessment.mitigation_name
                    if assessment.note:
                        name_with_note = f"{name} ({assessment.note})"
                    else:
                        name_with_note = name

                    if assessment.status == "already_in_place":
                        in_place.append(name_with_note)
                    else:
                        missing.append(name_with_note)

                # Auto-correct: add any unassessed mitigations to "missing"
                assessed_bases = {
                    a.mitigation_name for a in audit_result.mitigations_assessment
                }
                for m in all_mits:
                    if m not in assessed_bases:
                        missing.append(m)

                threat["mitigations_already_in_place"] = in_place
                threat["mitigations_missing"] = missing
                threat["ai_proposed_mitigations"] = audit_result.ai_proposed_mitigations
                threat["remaining_risk"] = audit_result.remaining_risk

                # Write updated file
                threats_data["threats"] = threats
                THREATS_JSON_PATH.write_text(
                    json.dumps(threats_data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                typer.echo(
                    f"    ✓ {threat.get('element')} — {len(in_place)} in place, {len(missing)} missing"
                )
            else:
                typer.echo(f"    ❌ No result for threat {i} — skipping")

        # --- Step 5: Convert to CSV ---
        typer.echo("\n📊 Converting to CSV...")
        csv_result = convert_to_csv_from_file()
        typer.echo(f"   ✓ {csv_result}")

    typer.echo(f"\n✅ Done. Outputs written to: {OUTPUTS_DIR}")
