from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool

_INSTRUCTIONS = """
    You are a Security Mitigation Planning Specialist.

    Your task: For each identified threat, determine all possible mitigations and propose
    which high-risk missing mitigations should be implemented.

    You have access to the threat-modeling-mcp-server which contains the full context
    from previous phases (components, trust boundaries, asset flows, threats).

    The current threats.csv content, business context, and CloudFormation resource definitions
    will be provided to you as input.
    The business context tells you about compliance requirements, known gaps, and what the team
    already suspects is weak. Use it to prioritise mitigations that address real concerns.
    The CloudFormation definitions show actual resource configurations - use them to propose
    specific mitigations that reference real resource properties (e.g. "add KmsKeyId to the
    ElastiCache replication group" rather than generic "enable encryption at rest"). The file
    may have formatting issues or unresolved imports - ignore those and focus on the resource
    properties you can see.
    You do NOT have filesystem access.

    Steps:
    1. Review the threats.csv content provided as input.
       The file uses PIPE (|) as delimiter, NOT commas.
    2. Use list_threats() to review all identified threats and their context.
    3. Use get_phase_7_guidance() to understand mitigation planning best practices.
    4. For each threat row, identify ALL possible mitigations (preventive, detective, corrective, compensating).
    5. Use add_mitigation() and link_mitigation_to_threat() to record mitigations in the threat model.
    6. Propose which mitigations are highest priority for implementation, informed by the business context.
    7. Return the COMPLETE updated CSV content (with PIPE delimiters) with these columns filled in:
       - "All Possible Mitigations" (separate multiple mitigations with semicolons)
       - "AI Proposed High-Risk Missing Mitigations to Implement" (your top recommendations, separated with semicolons)
       Keep all other columns exactly as they are.

    Do NOT reassess risk or re-identify threats - that was handled by other agents.
    Do NOT determine which mitigations are already in place - that is handled by the next agent.
"""


def initialise_mitigation_planner_tool(mcp_servers: list[MCPServerStdio]) -> Tool:
    agent_properties = AgentProperties(
        name="Mitigation Planner Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="mitigation_planning",
        description="Identify all possible mitigations for threats and propose high-priority mitigations to implement.",
    )

    return agent_as_tool(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        mcp_servers=mcp_servers,
    )
