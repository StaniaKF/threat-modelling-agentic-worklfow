# Business Context

## Project / Service Name
Serverless Ingestion Service

## What does this system do?
This system provides an API endpoint for users to submit data requests. It validates and processes the incoming payload via a serverless execution environment, captures operational tracking logs, and persists the resulting updates into a structured database.

## Critical Components
List the components that are most important to protect and why. Include physical id in brackets.

- **API Gateway (APIGW)**: Public-facing entry point. Handles all customer API requests and requires strict throttling and authorization rules.
- **Lambda Function (Lambda)**: Core business logic. Processes user payloads, formats database items, and handles secure integrations.
- **DynamoDB Table (Dynamo)**: Persistent data store. Contains system records and application state data that must be protected from unauthorized changes.

## Sensitive Data
What sensitive data flows through the system?

- User payload attributes and submission data
- Operational and error logs containing transaction details
- Persistent state records stored within the database

## Compliance / Regulatory Requirements
Any standards or regulations that apply (e.g. GDPR, PCI-DSS, SOC2).

- GDPR (user data protection)
- SOC2 (operational security and availability)

## AWS Account Info
- Account: 869935085853
- Region: eu-west-1
- Physical IDs are in brackets in the diagram, e.g. APIGW, Lambda, CW, Dynamo

## Trust Assumptions
What do we trust? What don't we trust?

- We trust: IAM-authorized interactions between Lambda, CloudWatch, and DynamoDB
- We don't trust: Unauthenticated payloads hitting the API Gateway endpoint
- We don't trust: Inbound public internet traffic without protocol filtering

## Known Gaps / Areas of Concern
Anything you already know is weak or needs attention.

- No WAF currently configured in front of the API Gateway
- Data at rest encryption needs verification against custom KMS keys instead of default AWS managed keys