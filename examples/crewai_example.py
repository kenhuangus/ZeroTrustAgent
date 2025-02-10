import os
import logging
import sys
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, LLM
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

        # Create LLM instance following the proper configuration using Together AI wrapper
        llm = LLM(
            model="together_ai/meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo-128K",
            base_url="https://api.together.xyz",
            api_key=os.getenv("TOGETHER_API_KEY")
        )

        # Create the agent instantiating it with the proper LLM and any additional parameters
        agent_config = {
            "agent_id": agent_id,
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

def create_secure_task(description: str, agent: Agent, agent_id: str, expected_output: str = "") -> Task:
    """
    Create a secure task for an agent while providing all required fields.

    Parameters:
        description (str): Description of the task.
        agent (Agent): The agent for which the task is created.
        agent_id (str): Identifier for the agent (for logging/auditing purposes).
        expected_output (str): The expected output for the task (default: empty string).

    Returns:
        Task: A new Task instance with the required 'expected_output' field set.
    """
    try:
        task = Task(
            description=description,
            agent=agent,
            expected_output=expected_output
        )
        logger.info(f"Successfully created secure task for agent: {agent_id}")
        return task
    except Exception as e:
        logger.error(f"Error creating secure task for agent {agent_id}: {str(e)}")
        raise

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Initialize our Together AI wrapper
    llm = LLM(
        model="together_ai/meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo-128K",
        base_url="https://api.together.xyz",
        api_key=os.getenv("TOGETHER_API_KEY")
    )
   
    # Create researcher agent
    researcher = Agent(
        role='Research Analyst',
        goal='Research AI developments',
        backstory='Expert at gathering and analyzing information',
        verbose=True,
        allow_delegation=False,
        llm=llm
    )

    # Create writer agent
    writer = Agent(
        role='Content Writer',
        goal='Write clear summaries',
        backstory='Expert at creating concise content',
        verbose=True,
        allow_delegation=False,
        llm=llm
    )

    # Create tasks
    research_task = Task(
        description='Research the latest developments in artificial intelligence',
        expected_output='A comprehensive analysis of recent AI developments and breakthroughs',
        agent=researcher
    )

    writing_task = Task(
        description='Write a summary of the AI developments in simple terms',
        expected_output='A clear and concise summary of AI developments that anyone can understand',
        agent=writer
    )

    # Create and run the crew
    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, writing_task],
        verbose=True
    )

    try:
        # Run the crew and get results
        result = crew.kickoff()
        print("\nFinal Result:")
        print(result)
    except Exception as e:
        print(f"Error running crew: {str(e)}")

if __name__ == "__main__":
    main()