"""
CrewAI Integration Example with Zero Trust Security Agent
"""

import os
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatOllama
import google.generativeai as genai
from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool
import logging
import sys
import time
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
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

class GeminiChatModel:
    """Wrapper for Google's Gemini model to make it compatible with CrewAI."""

    def __init__(self):
        google_api_key = os.environ.get('GOOGLE_API_KEY')
        if not google_api_key:
            raise ValueError("Google API key not found")

        logger.info("Initializing Gemini LLM...")
        genai.configure(api_key=google_api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.temperature = 0.7

    def complete(self, prompt):
        """Complete a prompt."""
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error in Gemini generate: {str(e)}")
            raise

    def __call__(self, prompt):
        """Make the model callable for CrewAI compatibility."""
        return self.complete(prompt)

def get_llm():
    """Get the Gemini LLM."""
    try:
        return GeminiChatModel()
    except Exception as e:
        logger.error(f"Failed to initialize Gemini: {str(e)}")
        raise

@retry(
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
    reraise=True
)
def create_secure_agent(agent_id: str, token: str):
    """Create a secure agent with ZTA validation."""
    logger.info(f"Creating secure agent: {agent_id}")

    try:
        # Initialize tools and models
        tools = [SecureSearchTool()]
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

        time.sleep(5)  # Delay after agent creation
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
        task_context = {
            'type': 'research' if 'research' in task_description.lower() else 'analyze',
            'description': task_description
        }

        if crewai_adapter.secure_task_execution(task_context, agent_id, token):
            logger.info(f"Task creation approved for agent {agent_id}")
            time.sleep(3)
            return Task(
                description=task_description,
                expected_output="A comprehensive report detailing findings and recommendations",
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
            logger.info("Creating research agent...")
            researcher = create_secure_agent("research_agent", token)
            time.sleep(5)

            logger.info("Creating analyst agent...")
            analyst = create_secure_agent("analyst_agent", token)
            time.sleep(5)

            logger.info("Creating research task...")
            research_task = create_secure_task(
                "Research current AI security best practices and create a detailed report",
                researcher,
                "research_agent",
                token
            )
            time.sleep(3)

            logger.info("Creating analysis task...")
            analysis_task = create_secure_task(
                "Analyze the security findings and provide recommendations",
                analyst,
                "analyst_agent",
                token
            )
            time.sleep(3)

            logger.info("Creating and starting crew...")
            crew = Crew(
                agents=[researcher, analyst],
                tasks=[research_task, analysis_task],
                verbose=True,
                process=Process.sequential
            )

            time.sleep(5)

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