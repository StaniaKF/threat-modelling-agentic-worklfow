import os
from openai import AsyncOpenAI
from agents import Agent, OpenAIChatCompletionsModel
from constants import MODEL


def create_client() -> AsyncOpenAI:
    """Create an AsyncOpenAI client with environment variables."""
    return AsyncOpenAI(
        base_url=os.getenv("LITELLM_API_BASE_URL"),
        api_key=os.getenv("LITELLM_API_KEY"),
        timeout=300.0,
    )


def create_agent(
    name: str,
    instructions: str,
    client: AsyncOpenAI,
    mcp_servers: list,
    model: str = MODEL,
) -> Agent:
    """Helper factory to keep agent instantiation clean and uniform."""
    return Agent(
        name=name,
        instructions=instructions,
        model=OpenAIChatCompletionsModel(model=model, openai_client=client),
        mcp_servers=mcp_servers,
    )
