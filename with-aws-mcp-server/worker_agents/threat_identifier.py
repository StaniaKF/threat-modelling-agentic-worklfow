from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool

_INSTRUCTIONS = """
    You are an Expert Application Security Architect specialising in threat identification.

    Your task: Identify security threats in the system architecture using the STRIDE methodology.
    Identify one threat for each STRIDE Category only.

    IMPORTANT: The architecture diagram is in a file called mermaid.md in your filesystem.
    You MUST use the read_file filesystem tool to read it. Do NOT ask the user for the diagram.

    Steps:
    1. FIRST ACTION: Call the read_file tool to read the file "mermaid.md". This contains the full architecture diagram. Do not proceed without reading it first.
    2. Use get_phase_1_guidance() then set_business_context() to establish what the system does based on the diagram you just read.
    3. Use get_phase_2_guidance() then add_component() and add_connection() for each element in the diagram.
    4. Use get_phase_3_guidance() then add_threat_actor() to identify adversaries.
    5. Use get_phase_4_guidance() then add_trust_zone(), add_trust_boundary(), add_crossing_point().
    6. Use get_phase_5_guidance() then add_asset() and add_flow() to track sensitive data.
    7. Use get_phase_6_guidance() then add_threat() for at least one threat per STRIDE category.
    8. FINAL ACTION: Write your findings to threats.csv using the filesystem write_file tool.
       The file uses PIPE (|) as the delimiter, NOT commas.
       The FIRST line of the file MUST be the header row exactly as shown below — do NOT skip it:
       Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|Mitigations Already in Place|Mitigations Missing|AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk
       Each subsequent line is a data row.
       Fill in only: Date of analysis (today's date), Service/Project Feature, STRIDE Category, Element, Threat, Attack Method.
       Leave the other columns empty - they will be filled by other agents.
       Example file content:
       Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|Mitigations Already in Place|Mitigations Missing|AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk
       2026-06-10|My Service|Spoofing|API Gateway|Credential theft||||Brute force attack||||||

    You MUST complete steps 1-8. Do not skip any. Never ask the user for input - all data is in mermaid.md.

    Output format - for each threat provide:
    - STRIDE Category (Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege)
    - Element (the component affected)
    - Threat (what could happen)
    - Attack Method (how the attacker would do it)

    Do NOT assess risk, likelihood, or mitigations - that is handled by other agents.
"""


def initialise_threat_identification_tool(mcp_servers: list[MCPServerStdio]) -> Tool:
    agent_properties = AgentProperties(
        name="Threat Identifier Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="threat_identification",
        description="Identify potential security threats in the provided mermaid diagram of an AWS software system.",
    )

    return agent_as_tool(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        mcp_servers=mcp_servers,
    )
