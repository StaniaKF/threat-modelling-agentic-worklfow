# Threat Modelling Agentic Workflow

A repo containing experimental projects that explore agentic workflows for automated threat modelling.

## Projects

### [with-aws-mcp-server](./with-aws-mcp-server)

An agentic pipeline that uses MCP (Model Context Protocol) servers to automate STRIDE-based threat modelling:

- **Threat Modeling MCP Server** — provides structured guidance for threat identification (phases, STRIDE categories, trust boundaries, etc.)
- **AWS MCP Server** — queries the live AWS environment to discover which mitigations are already in place

> ⚠️ **Known issue:** The AWS MCP server is currently timing out during mitigation audit calls. Investigation is ongoing.
