"""
CrewAI Integration Example with Zero Trust Security Agent
"""

from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatOllama
from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool
import logging
import sys
import os
import time
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging with more detailed configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize ZTA components
logger.info("Initializing Zero Trust Security Agent...")
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']
auth_manager = zta_components['auth_manager']

def get_llm():
    """Get the appropriate LLM based on configuration."""
    # Check if remote LLM is enabled in .env
    use_remote_llm = os.getenv('USE_REMOTE_LLM', 'true').lower() == 'true'  # Default to true for Replit

    if use_remote_llm:
        logger.info("Using OpenAI as LLM provider")
        openai_key = os.getenv('OPENAI_API_KEY')
        if not openai_key:
            raise ValueError("OpenAI API key not found. Please set OPENAI_API_KEY in your environment.")

        try:
            return ChatOpenAI(
                model="gpt-3.5-turbo",
                temperature=0.7,
                request_timeout=120,
                max_retries=5
            )
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI: {str(e)}")
            raise

    # If remote LLM is disabled, try Ollama
    logger.info("Remote LLM disabled. Attempting to use local Ollama (llama2)")
    try:
        logger.debug("Creating Ollama instance with llama2 model")
        ollama = ChatOllama(
            model="llama2",
            timeout=30,
            base_url="http://localhost:11434",
            temperature=0.7
        )

        # Test the Ollama connection with retry logic
        try:
            logger.debug("Testing Ollama connection...")
            for attempt in range(3):
                try:
                    test_response = ollama.invoke("test")
                    logger.info("Successfully connected to Ollama")
                    return ollama
                except Exception as e:
                    if attempt < 2:
                        logger.warning(f"Ollama connection attempt {attempt + 1} failed: {str(e)}")
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        raise
        except Exception as e:
            logger.error(f"All Ollama connection attempts failed: {str(e)}")
            raise

    except Exception as e:
        logger.warning(f"Failed to initialize Ollama: {str(e)}")

        # If we have OpenAI credentials, use as fallback
        if os.getenv('OPENAI_API_KEY'):
            logger.info("Falling back to OpenAI as LLM provider")
            return ChatOpenAI(
                model="gpt-3.5-turbo",
                temperature=0.7,
                request_timeout=120,
                max_retries=5
            )
        else:
            raise RuntimeError(
                "Failed to initialize local Ollama and no OpenAI API key available. "
                "Please either ensure Ollama is running locally or set up OpenAI credentials."
            )

def create_secure_agent(agent_id: str, token: str):
    """Create a secure agent with ZTA validation."""
    logger.info(f"Creating secure agent: {agent_id}")

    try:
        # Initialize tools and models with retry logic
        tools = [SecureSearchTool()]

        # Get the configured LLM
        llm = get_llm()

        agent = Agent(
            role="Security Researcher",
            goal="Research and analyze security practices securely and efficiently",
            backstory="An AI security researcher with expertise in analyzing security practices and implementing secure solutions",
            verbose=True,
            allow_delegation=False,
            tools=tools,
            llm=llm
        )

        # Add significant delay after agent creation to avoid rate limits
        time.sleep(5)  # Increased delay to 5 seconds
        return agent
    except Exception as e:
        logger.error(f"Error creating agent {agent_id}: {str(e)}")
        raise

@retry(
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
    reraise=True
)
def create_secure_task(task_description: str, agent: Agent, agent_id: str, token: str) -> Task:
    """Create a task with security validation."""
    logger.info(f"Creating secure task for agent {agent_id}")

    try:
        # Validate the task creation
        task_context = {
            'type': 'research' if 'research' in task_description.lower() else 'analyze',
            'description': task_description
        }

        if crewai_adapter.secure_task_execution(task_context, agent_id, token):
            logger.info(f"Task creation approved for agent {agent_id}")
            # Add delay after successful task creation
            time.sleep(3)  # Increased delay to 3 seconds
            return Task(
                description=task_description,
                expected_output="A detailed report with findings and recommendations",
                agent=agent
            )
        else:
            logger.warning(f"Task creation denied for agent {agent_id}")
            raise PermissionError(f"Security policy violation for task: {task_description}")
    except Exception as e:
        logger.error(f"Error creating task for agent {agent_id}: {str(e)}")
        raise

def main():
    try:
        logger.info("Starting CrewAI integration demo")

        # Get token for authentication
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

        try:
            # Create secure agents with retry logic and increased delays
            logger.info("Creating research agent...")
            researcher = create_secure_agent("research_agent", token)
            time.sleep(5)  # Increased delay between agent creations

            logger.info("Creating analyst agent...")
            analyst = create_secure_agent("analyst_agent", token)
            time.sleep(5)  # Increased delay after last agent creation

            # Create tasks with security validation
            logger.info("Creating research task...")
            research_task = create_secure_task(
                "Research current AI security best practices and create a detailed report",
                researcher,
                "research_agent",
                token
            )
            time.sleep(3)  # Add delay between task creations

            logger.info("Creating analysis task...")
            analysis_task = create_secure_task(
                "Analyze the security findings and provide recommendations",
                analyst,
                "analyst_agent",
                token
            )
            time.sleep(3)  # Add delay between task creation and crew setup

            # Create and run crew with proper error handling
            logger.info("Creating and starting crew...")
            crew = Crew(
                agents=[researcher, analyst],
                tasks=[research_task, analysis_task],
                verbose=True,
                process=Process.sequential  # Ensure sequential execution to avoid concurrent API calls
            )

            # Add delay before starting crew execution
            time.sleep(5)  # Increased delay before crew execution

            result = crew.kickoff()
            logger.info("Crew execution completed")
            print("Crew execution result:", result)

        except PermissionError as e:
            logger.error(f"Security policy violation: {str(e)}")
            print(f"Security Error: {str(e)}")
        except Exception as e:
            logger.error(f"Error during task execution: {str(e)}")
            print(f"Task Error: {str(e)}")

    except Exception as e:
        logger.error(f"Error in CrewAI integration demo: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()