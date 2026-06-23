"""
Mitigation Auditor — uses structured output to return per-mitigation assessments.

The agent queries AWS and CloudFormation to determine which mitigations are in place,
then returns a structured response. Python handles the file write.
"""

from enum import StrEnum

from pydantic import BaseModel


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
    note: str = ""  # optional note (e.g. "partial — connect timeout only")


class ThreatAuditResult(BaseModel):
    """Structured output from the auditor for a single threat."""

    mitigations_assessment: list[MitigationAssessment]
    ai_proposed_mitigations: list[str]
    remaining_risk: RemainingRisk


INSTRUCTIONS = """
    You are a Cloud Security Auditor specialising in AWS infrastructure.

    Your task: For ONE SPECIFIC THREAT provided in the input, determine which of its
    mitigations are already in place and which are missing. You have AWS MCP access to
    query live infrastructure.

    INPUTS PROVIDED:
    - The specific threat object (JSON) including its all_possible_mitigations list
    - AWS account ID and region
    - Relevant CloudFormation resource definitions (if provided) for the affected component

    Use the AWS MCP tools to verify which mitigations are in place.
    If CloudFormation configuration is provided, use it as evidence when AWS calls fail
    or services are unsupported.
    Keep queries minimal and targeted (max 5-6 calls). If both AWS and CloudFormation
    provide no evidence for a mitigation, mark it as "missing".

    YOUR RESPONSE:
    Return a structured assessment with:
    1. mitigations_assessment: For EACH item in all_possible_mitigations, provide:
       - mitigation_name: The EXACT text from all_possible_mitigations
       - status: Either "already_in_place" or "missing" or "partially_in_place"
       - note: Optional explanation (e.g. "partial — connect timeout configured but no read timeout")
    2. ai_proposed_mitigations: From the "missing" items, select the highest priority ones
       with a brief explanation of why (e.g. "Enable 2FA — critical for public-facing auth")
    3. remaining_risk: "Critical", "High", "Medium", or "Low" after considering what's in place

    IMPORTANT:
    - You MUST assess EVERY item in all_possible_mitigations — do not skip any
    - Use EXACT text for mitigation_name (copy it from the input)
    - Use AWS MCP to verify actual configurations where possible
    - Use FILTERED queries (e.g. --group-ids, --function-name) to avoid timeouts
    - Start with `aws sts get-caller-identity` to warm up the connection

    UNSUPPORTED AWS SERVICES (do NOT call — fall back to CloudFormation):
    - configservice (AWS Config)
    - inspector / aws inspector2
    - guardduty
    - securityhub
    - macie
    - elasticache (ElastiCache)
    - api-gateway
    - cognito

    SUPPORTED SERVICES: ec2, iam, lambda, logs, cloudwatch, cloudtrail,
    wafv2, shield, sts, s3, kms, secretsmanager, ssm

    If an AWS call fails after retries, fall back to CloudFormation evidence.
    If neither AWS nor CloudFormation has relevant info, mark as "missing".
"""
