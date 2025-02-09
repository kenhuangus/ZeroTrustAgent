"""
CrewAI Integration Example for Zero Trust Security Agent
"""

import os
import logging
import sys
from typing import Any, List, Dict, Optional
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process
from langchain.callbacks.manager import CallbackManagerForLLMRun
from langchain.schema import LLMResult
from langchain.llms.base import LLM
from litellm import completion
from pydantic import BaseModel, Field

from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize ZTA components
logger.info("Initializing Zero Trust Security Agent...")
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']
auth_manager = zta_components['auth_manager']

class TogetherLLMConfig(BaseModel):
    api_key: str = Field(..., description="Together AI API key")
    model_name: str = Field(
        default="together_ai/togethercomputer/Llama-2-7B-32K-Instruct",
        description="Model identifier"
    )
    temperature: float = Field(default=0.7, description="Sampling temperature")
    max_tokens: int = Field(default=512, description="Maximum tokens to generate")

class TogetherLLM(LLM):
    """Custom LLM class for Together AI integration using liteLLM."""

    config: TogetherLLMConfig

    def __init__(self, **kwargs):
        """Initialize the LLM."""
        config = TogetherLLMConfig(**kwargs)
        super().__init__()
        self.config = config
        os.environ["TOGETHERAI_API_KEY"] = config.api_key

    @property
    def _llm_type(self) -> str:
        """Return type of LLM."""
        return "together_ai"

    def _call(self, prompt: str, stop: Optional[List[str]] = None, run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs) -> str:
        """Execute the LLM call using liteLLM."""
        try:
            messages = [{"role": "user", "content": prompt}]
            response = completion(
                model=self.config.model_name,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stop=stop
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Together AI API call failed: {str(e)}")
            raise

@retry(
    wait=wait_exponential(multiplier=1, min=4, max=10),
    stop=stop_after_attempt(3),
    reraise=True
)
def create_secure_agent(agent_id: str, token: str) -> Agent:
    """Create a secure agent with ZTA validation."""
    logger.info(f"Creating secure agent: {agent_id}")

    try:
        # Initialize tools with retry logic
        tools = [SecureSearchTool()]

        # Get Together AI API key from environment
        together_api_key = os.environ.get('TOGETHER_API_KEY')
        if not together_api_key:
            raise ValueError("Together API key not found in environment")

        # Create LLM instance with proper configuration
        llm = TogetherLLM(
            api_key=together_api_key,
            model_name="together_ai/togethercomputer/Llama-2-7B-32K-Instruct",
            temperature=0.7,
            max_tokens=512
        )

        # Create agent with specific role
        agent = Agent(
            role=f"AI Security {agent_id.replace('_', ' ').title()}",
            goal="Research and analyze security practices securely and efficiently",
            backstory="An AI security specialist with expertise in analyzing security practices and implementing secure solutions",
            verbose=True,
            allow_delegation=False,
            tools=tools,
            llm=llm
        )

        logger.info(f"Successfully created agent: {agent_id}")
        return agent

    except Exception as e:
        logger.error(f"Error creating agent {agent_id}: {str(e)}")
        raise

def main():
    """Run the CrewAI integration example."""
    try:
        logger.info("Starting CrewAI integration demo")

        # Authenticate research agent
        credentials = {
            "identity": "research_agent",
            "secret": "secret123"
        }
        logger.info("Authenticating research agent...")
        token = auth_manager.authenticate(credentials)

        if not token:
            logger.error("Authentication failed")
            return

        logger.info("Authentication successful")

        # Create and execute tasks
        try:
            # Create research agent
            researcher = create_secure_agent("research_agent", token)
            analyst = create_secure_agent("analyst_agent", token)

            # Create tasks
            research_task = Task(
                description="Research current AI security best practices and create a detailed report",
                agent=researcher
            )

            analysis_task = Task(
                description="Analyze the security findings and provide recommendations",
                agent=analyst
            )

            # Create and execute crew
            crew = Crew(
                agents=[researcher, analyst],
                tasks=[research_task, analysis_task],
                verbose=True,
                process=Process.sequential
            )

            result = crew.kickoff()
            logger.info("Crew execution completed")
            print("Result:", result)

        except Exception as e:
            logger.error(f"Error during task execution: {str(e)}")
            print(f"Task Error: {str(e)}")

    except Exception as e:
        logger.error(f"Error in CrewAI integration demo: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()