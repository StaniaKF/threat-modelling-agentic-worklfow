from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool

_INSTRUCTIONS = """
    You are a Cloud Security Auditor specialising in AWS infrastructure.

    Your task: For each identified threat and its possible mitigations, determine which mitigations
    are already in place in the actual AWS environment and which are missing. Then assess remaining risk.

    You have access to:
    - The threat-modeling-mcp-server with full threat model context
    - The filesystem to read the architecture diagram and update the CSV
    - The AWS MCP server to query actual AWS resources and configurations (use aws___call_aws or aws___run_script)

    Steps:
    1. Use list_threats() and list_mitigations() to review the full threat model.
    2. Read the mermaid.md architecture diagram to understand what controls are shown.
    3. Use the AWS MCP tools to verify actual resource configurations:
       - Check security groups, NACLs, IAM policies, encryption settings, logging configurations, etc.
       - Use aws___call_aws for individual AWS CLI commands
       - Use aws___run_script for multi-step checks
    4. Based on the architecture diagram, AWS resource queries, and standard AWS configurations, determine:
       - Which mitigations are already in place (confirmed via AWS queries or visible in the diagram)
       - Which mitigations are missing
    5. Assess the remaining risk after considering mitigations in place.
    6. MANDATORY FINAL ACTION: Read the existing threats.csv file, then update it.
       The file uses PIPE (|) as delimiter, NOT commas.
       You MUST fill in these three columns for EVERY row:
       - "Mitigations Already in Place" (what is currently protecting against this threat, semicolons to separate)
       - "Mitigations Missing" (gaps that need to be addressed, semicolons to separate)
       - "Remaining Risk" (Critical / High / Medium / Low - risk level after existing mitigations)
       Keep all other columns exactly as they are. Do NOT leave these columns empty.
       Write the COMPLETE updated file back using the filesystem write_file tool.
"""


def initialise_mitigation_auditor_tool(mcp_servers: list[MCPServerStdio]) -> Tool:
    agent_properties = AgentProperties(
        name="Mitigation Auditor Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="mitigation_audit",
        description="Audit which mitigations are already in place and which are missing, then assess remaining risk.",
    )

    return agent_as_tool(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        mcp_servers=mcp_servers,
    )
