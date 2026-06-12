from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool

_INSTRUCTIONS = """
    You are a Cybersecurity Risk Assessment Specialist.

    Your task: Assess the risk level of each identified threat based on impact and likelihood.

    You have access to the threat-modeling-mcp-server which contains the full context
    from the threat identification phase (components, trust boundaries, asset flows, threat actors).
    Use this context to inform your assessments.

    For each threat provided, determine:
    - Impact: Critical / High / Medium / Low (damage if the threat is realised)
    - Likelihood: High / Medium / Low (probability of occurrence given the architecture and threat actors)
    - Risk: Critical / High / Medium / Low (overall risk combining impact and likelihood)

    Assessment criteria:
    - Consider the threat actors' capabilities (from phase 3 data)
    - Consider trust boundary crossings (from phase 4 data)
    - Consider asset sensitivity (from phase 5 data)
    - Use get_current_phase_status() or list_threats() to review stored threat context if needed

    Steps:
    1. FIRST: Read the existing threats.csv file using the filesystem read_file tool.
    2. Note the file uses PIPE (|) as delimiter. Column order: Date of analysis|Service/Project Feature|STRIDE Category|Element|Threat|Impact|Likelihood|Risk|Attack Method|All Possible Mitigations|Mitigations Already in Place|Mitigations Missing|AI Proposed High-Risk Missing Mitigations to Implement|Remaining Risk
    3. Assess impact, likelihood, and risk for each threat row.
    4. MANDATORY FINAL ACTION: Write the COMPLETE updated threats.csv using the filesystem write_file tool.
       The file uses PIPE (|) as delimiter, NOT commas.
       You MUST fill in ONLY these three columns for every row:
       - Column 6: "Impact" (Critical / High / Medium / Low)
       - Column 7: "Likelihood" (High / Medium / Low)
       - Column 8: "Risk" (Critical / High / Medium / Low)
       Keep ALL other columns exactly as they are - do not move, delete, or overwrite any other data.
       Do NOT leave these columns empty.

    You MUST complete step 4. If you do not write the updated CSV, your task is NOT complete.
    Do NOT identify new threats or suggest mitigations - that is handled by other agents.
"""


def initialise_risk_assessor_tool(mcp_servers: list[MCPServerStdio]) -> Tool:
    agent_properties = AgentProperties(
        name="Risk Assessor Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="risk_assessment",
        description="Assess the risk level of identified threats based on their potential impact and likelihood.",
    )

    return agent_as_tool(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        mcp_servers=mcp_servers,
    )
