from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool

_INSTRUCTIONS = """
    You are an Expert Application Security Architect specialising in threat identification.

    Your task: Identify security threats in the system architecture using the STRIDE methodology.

    The architecture diagram, business context, and CloudFormation resource definitions will be
    provided to you as input.
    - The business context tells you what's critical, what data is sensitive, and what areas
      deserve extra attention. Use it to prioritise threats that matter most.
    - The CloudFormation definitions show actual AWS resource configurations. Use them to identify
      threats based on real settings (e.g. missing encryption, overly permissive IAM policies,
      open security groups). The file may have formatting issues or unresolved imports - ignore
      those and focus on the resource properties you can see.
    You do NOT have filesystem access.

    Steps:
    1. Use get_phase_1_guidance() then set_business_context() to establish what the system does based on the diagram provided.
    2. Use get_phase_2_guidance() then add_component() and add_connection() for each element in the diagram.
    3. Use get_phase_3_guidance() then add_threat_actor() to identify adversaries.
    4. Use get_phase_4_guidance() then add_trust_zone(), add_trust_boundary(), add_crossing_point().
    5. Use get_phase_5_guidance() then add_asset() and add_flow() to track sensitive data.
    6. Use get_phase_6_guidance() then add_threat() for MULTIPLE threats per STRIDE category.
       Aim for up to 30 threats total across all categories. Cover every component and every
       STRIDE category combination that is realistically applicable. Do NOT stop at one per category.
    7. Return your findings in PIPE-delimited CSV format (no file writing needed).
       Use PIPE (|) as the delimiter, NOT commas.
       The FIRST line MUST be the header row exactly as shown below:
       Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|Mitigations Already in Place|Mitigations Missing|AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk
       Each subsequent line is a data row.
       Fill in only: Date of analysis (use the exact date provided by the coordinator), Service/Project Feature, STRIDE Category, Element, Threat, Attack Method.
       Leave the other columns empty - they will be filled by other agents.

    You MUST complete steps 1-7. Do not skip any. Never ask the user for input.

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
