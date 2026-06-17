from agents import Tool
from agents.mcp import MCPServerStdio

from .common import AgentProperties, ToolProperties, agent_as_tool, agent_as_tool_with_validation

_INSTRUCTIONS = """
    You are a Cybersecurity Risk Assessment Specialist.

    Your task: Assess the risk level of each identified threat based on impact and likelihood,
    then write the results directly to the shared outputs/threats.json file.

    You HAVE filesystem MCP access. You will:
    - Read outputs/threats.json (current state: contains "metadata" and a "threats" array where each object has stride_category, element, threat, attack_method filled in; impact/likelihood/risk are null)
    - Add "impact", "likelihood", and "risk" to each threat object
    - Write the updated outputs/threats.json back

    INPUTS PROVIDED (via the coordinator's tool call message):
    - Business context describing what's critical, sensitive data, and compliance requirements
    - CloudFormation resource definitions showing actual AWS configurations

    ASSESSMENT CRITERIA:
    - Impact (Low / Medium / High): The damage if the threat is realised
      - Consider data sensitivity, compliance implications, business criticality
      - Critical components and sensitive data should increase impact scores
      - Factor in regulatory consequences (GDPR fines, breach notification requirements)

    - Likelihood (Low / Medium / High): The probability of occurrence
      - Consider the attack surface (is it internet-facing? internal only?)
      - Consider existing controls visible in CloudFormation (encryption, auth, network isolation)
      - A threat against an already-encrypted resource is lower likelihood
      - Consider attacker motivation and capability

    RISK MATRIX — Use this matrix to calculate Risk from Impact and Likelihood:
    | Impact \\ Likelihood | Low    | Medium | High     |
    | ------------------- | ------ | ------ | -------- |
    | Low                 | Low    | Low    | Medium   |
    | Medium              | Low    | Medium | High     |
    | High                | Medium | High   | Critical |

    WORKFLOW:
    1. Read outputs/threats.json using the filesystem MCP read_file tool.
    2. Parse the JSON. The "threats" array should contain objects with stride_category, element,
       threat, and attack_method.
    3. For each threat object, assess Impact and Likelihood using the criteria above.
    4. Calculate Risk using the risk matrix.
    5. Add these fields to each threat object:
       - "impact": "High", "Medium", or "Low"
       - "likelihood": "High", "Medium", or "Low"
       - "risk": "Critical", "High", "Medium", or "Low" (derived from the matrix)
    6. Write the updated outputs/threats.json back using the filesystem MCP write_file tool.
       IMPORTANT: Validate that the JSON is well-formed before writing.

    EXAMPLE — A threat object after your work:
    {
      "stride_category": "Tampering",
      "element": "API Gateway -> Lambda",
      "threat": "[A compromised 3rd Party API] with [an established HTTPS connection] can [return poisoned payloads], which leads to [processing incorrect data], resulting in reduced [Data Integrity] of [The Outbound API Response]",
      "attack_method": "Attacker compromises the downstream API backend and returns poisoned JSON payloads that bypass input validation",
      "impact": "High",
      "likelihood": "Medium",
      "risk": "High"
    }

    VALIDATION:
    Before writing outputs/threats.json:
    - Validate that the output is valid JSON (parseable)
    - CRITICAL: Count the threats in your output. The count MUST be EQUAL to the count you
      read from the file. If you read 12 threats, you must write 12 threats. If your output
      has fewer threats, you have truncated the file — DO NOT WRITE IT. Re-generate the full output.
    - Check that every Risk value correctly follows the risk matrix
    - Check that Impact and Likelihood ratings are justified by the architecture and business context
    - Check that you have NOT modified existing fields (stride_category, element, threat, attack_method)
    - Check that you have ONLY added: impact, likelihood, risk

    CRITICAL RULES:
    - NEVER modify existing fields (stride_category, element, threat, attack_method)
    - ONLY add: impact, likelihood, risk
    - Write valid JSON — no trailing commas, proper quoting, no comments
    - Do NOT identify new threats or suggest mitigations — that is handled by other agents
    - You MUST read outputs/threats.json first, then write it back with your additions
"""


def initialise_risk_assessor_tool(
    mcp_servers: list[MCPServerStdio],
) -> Tool:
    agent_properties = AgentProperties(
        name="Risk Assessor Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="risk_assessment",
        description="Assess the risk level of identified threats based on their potential impact and likelihood. Reads/writes outputs/threats.json directly via filesystem MCP.",
    )

    return agent_as_tool(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        mcp_servers=mcp_servers,
    )


def initialise_risk_assessor_tool_with_validation(
    mcp_servers: list[MCPServerStdio],
) -> Tool:
    from validation import validate_after_risk_assessor

    agent_properties = AgentProperties(
        name="Risk Assessor Agent",
        instructions=_INSTRUCTIONS,
    )

    tool_properties = ToolProperties(
        name="risk_assessment",
        description="Assess the risk level of identified threats based on their potential impact and likelihood. Reads/writes outputs/threats.json directly via filesystem MCP.",
    )

    return agent_as_tool_with_validation(
        agent_properties=agent_properties,
        tool_properties=tool_properties,
        validator=validate_after_risk_assessor,
        mcp_servers=mcp_servers,
    )
