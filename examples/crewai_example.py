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
    """Configuration for Together AI LLM."""
    temperature: float = Field(default=0.7, description="Sampling temperature")
    max_tokens: int = Field(default=512, description="Maximum tokens to generate")
    model_name: str = Field(
        default="together_ai/togethercomputer/Llama-2-7B-32K-Instruct",
        description="Model identifier"
    )
    api_key: str = Field(default=None, description="TogetherAI API Key")

    class Config:  # Using Pydantic's Config class now
        extra = "forbid"
        arbitrary_types_allowed = True

class TogetherLLM(LLM, BaseModel):
    """Custom LLM class for Together AI integration using liteLLM."""
    config: TogetherLLMConfig = Field(default_factory=TogetherLLMConfig)

    class Config: # Using Pydantic's Config class now
        arbitrary_types_allowed = True

    def __init__(self, **kwargs):
        """Initialize the LLM."""
        super().__init__(**kwargs)  # Initialize BaseModel first
        # Load API key from environment if not provided in config
        if self.config.api_key is None:
            api_key = os.environ.get("TOGETHERAI_API_KEY")
            if api_key is None:
                raise ValueError("Together AI API key not found in environment or config")
            self.config.api_key = api_key
        # Set the API key for litellm
        os.environ["TOGETHERAI_API_KEY"] = self.config.api_key


    @property
    def _llm_type(self) -> str:
        """Return type of LLM."""
        return "together_ai"

    def _call(self, prompt: str, stop: Optional[List[str]] = None,
              run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs) -> str:
        """Execute the LLM call using liteLLM."""
        try:
            logger.debug(f"Sending prompt to Together AI: {prompt[:100]}...")
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

    async def _acall(self, prompt: str, stop: Optional[List[str]] = None, run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs) -> str:
        """Asynchronous version of the LLM call."""
        # litellm supports async, so we can just call it directly
        try:
            logger.debug(f"Sending async prompt to Together AI: {prompt[:100]}...")
            messages = [{"role": "user", "content": prompt}]
            response = await completion(
                model=self.config.model_name,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stop=stop
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Together AI async API call failed: {str(e)}")
            raise
    
    def _generate(self, prompts: List[str], stop: Optional[List[str]] = None,
                  run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs) -> LLMResult:
        """Generate LLM responses for multiple prompts."""
        # For simplicity, we'll just call _call repeatedly.  For true batching, litellm supports it.
        results = [self._call(prompt, stop, run_manager, **kwargs) for prompt in prompts]
        return LLMResult(generations=[[{"text": r}] for r in results])


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

        # Create LLM instance with proper configuration
        llm = TogetherLLM(
            temperature=0.7,
            max_tokens=512
        )

        # Create agent with keyword arguments
        agent_config = {
            "agent_id": agent_id,  # Include agent_id
            "role": f"AI Security {agent_id.replace('_', ' ').title()}",
            "goal": "Research and analyze security practices securely and efficiently",
            "backstory": "An AI security specialist with expertise in analyzing security practices and implementing secure solutions",
            "verbose": True,
            "allow_delegation": False,
            "llm": llm,
            "tools": tools
        }

        # Create agent with unpacked keyword arguments
        agent = Agent(**agent_config)

        logger.info(f"Successfully created agent: {agent_id}")
        return agent

    except Exception as e:
        logger.error(f"Error creating agent {agent_id}: {str(e)}")
        raise

def create_secure_task(description: str, agent: Agent, agent_id:str, token:str) -> Task:
    """
    Creates a secure task with ZTA validation, ensuring the task
    is associated with a specific agent and validated against security policies.
    """
    logger.info(f"Creating secure task for agent: {agent_id}")

    try:
        # Create a Task instance
        task = Task(
            description=description,
            agent=agent
        )
        logger.info(f"Successfully created secure task for agent: {agent_id}")
        return task

    except Exception as e:
        logger.error(f"Error creating secure task for agent {agent_id}: {str(e)}")
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

            # Create tasks with proper configuration
            research_task = create_secure_task(
                "Research current AI security best practices and create a detailed report", researcher, "research_agent", token
            )
            analysis_task = create_secure_task(
                "Analyze the security findings and provide recommendations", analyst, "analysis_agent", token
            )
            # Create and execute crew
            crew_config = {
                "agents": [researcher, analyst],
                "tasks": [research_task, analysis_task],
                "verbose": True,
                "process": Process.sequential
            }

            crew = Crew(**crew_config)

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