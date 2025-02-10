import os
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load environment variables from .env
load_dotenv()

class TogetherLLMConfig(BaseModel):
    """Configuration for Together AI LLM."""
    provider: str = Field(default="togetherai", description="LLM Provider name")
    temperature: float = Field(default=0.7, description="Sampling temperature")
    max_tokens: int = Field(default=512, description="Maximum tokens to generate")
    # Use a model name that includes the provider prefix (adjust as needed)
    model_name: str = Field(
        default="togetherai/togethercomputer/Llama-2-7B-32K-Instruct",
        description="Model identifier with provider prefix"
    )
    api_key: str = Field(
        default_factory=lambda: os.getenv("TOGETHERAI_API_KEY", "").strip(),
        description="TogetherAI API Key loaded from .env (variable: TOGETHERAI_API_KEY)"
    )

    class Config:
        extra = "forbid" 