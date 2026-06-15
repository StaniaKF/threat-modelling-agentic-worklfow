"""
Direct test: call the AWS MCP server tool without any agent layer.
This isolates whether the AWS proxy can actually execute API calls.
"""

import os
import asyncio
import time
import json
from contextlib import AsyncExitStack

from agents.mcp import MCPServerStdio
from dotenv import load_dotenv

from worker_agents import aws_mcp_params

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)


async def main():
    async with AsyncExitStack() as stack:
        aws_mcp_server = await stack.enter_async_context(
            MCPServerStdio(params=aws_mcp_params, client_session_timeout_seconds=300)
        )

        # 1. List tools and their schemas
        print("Listing tools...")
        tools = await aws_mcp_server.list_tools()
        print(f"\nAvailable tools ({len(tools)}):")
        for t in tools:
            print(f"\n  {t.name}:")
            print(f"    Description: {t.description[:100] if t.description else 'N/A'}")
            if t.inputSchema:
                print(f"    Input schema: {json.dumps(t.inputSchema, indent=6)}")

        # 2. Try a simple AWS CLI call - describe the API Gateway
        print("\n" + "=" * 60)
        print("Testing: describe API Gateway (lvzpzw2ls1)")
        print("=" * 60)

        start = time.time()
        try:
            result = await aws_mcp_server.call_tool(
                "aws___call_aws",
                {
                    "cli_command": "aws apigateway get-rest-api --rest-api-id lvzpzw2ls1 --region eu-west-1",
                },
            )
            elapsed = time.time() - start
            print(f"Success! ({elapsed:.1f}s)")
            print(f"Result: {result}")
        except Exception as e:
            elapsed = time.time() - start
            print(f"FAILED after {elapsed:.1f}s: {type(e).__name__}: {e}")

        # 3. Try another call - describe ElastiCache
        print("\n" + "=" * 60)
        print("Testing: describe ElastiCache replication groups")
        print("=" * 60)

        start = time.time()
        try:
            result = await aws_mcp_server.call_tool(
                "aws___call_aws",
                {
                    "cli_command": "aws elasticache describe-replication-groups --replication-group-id completed-dispatches-cache --region eu-west-1",
                },
            )
            elapsed = time.time() - start
            print(f"Success! ({elapsed:.1f}s)")
            print(f"Result: {result}")
        except Exception as e:
            elapsed = time.time() - start
            print(f"FAILED after {elapsed:.1f}s: {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
