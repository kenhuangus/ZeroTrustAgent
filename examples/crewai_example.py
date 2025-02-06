"""
CrewAI Integration Example with Zero Trust Security Agent
"""

from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool
import logging
import sys
import os

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

def create_secure_agent(agent_id: str, token: str):
    """Create a secure agent with ZTA validation."""
    logger.info(f"Creating secure agent: {agent_id}")

    # Initialize tools and models
    tools = [SecureSearchTool()]

    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.7
    )

    agent = Agent(
        role="Security Researcher",
        goal="Research and analyze security practices securely and efficiently",
        backstory="An AI security researcher with expertise in analyzing security practices and implementing secure solutions",
        verbose=True,
        allow_delegation=False,
        tools=tools,
        llm=llm
    )

    return agent

def create_secure_task(task_description: str, agent: Agent, agent_id: str, token: str) -> Task:
    """Create a task with security validation."""
    logger.info(f"Creating secure task for agent {agent_id}")

    # Validate the task creation
    task_context = {
        'type': 'research' if 'research' in task_description.lower() else 'analyze',
        'description': task_description
    }

    if crewai_adapter.secure_task_execution(task_context, agent_id, token):
        logger.info(f"Task creation approved for agent {agent_id}")
        return Task(
            description=task_description,
            agent=agent
        )
    else:
        logger.warning(f"Task creation denied for agent {agent_id}")
        raise PermissionError(f"Security policy violation for task: {task_description}")

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

        # Create secure agents
        researcher = create_secure_agent("research_agent", token)
        analyst = create_secure_agent("analyst_agent", token)

        try:
            # Create tasks with security validation
            research_task = create_secure_task(
                "Research current AI security best practices and create a detailed report",
                researcher,
                "research_agent",
                token
            )

            analysis_task = create_secure_task(
                "Analyze the security findings and provide recommendations",
                analyst,
                "analyst_agent",
                token
            )

            # Create and run crew
            logger.info("Creating and starting crew...")
            crew = Crew(
                agents=[researcher, analyst],
                tasks=[research_task, analysis_task],
                verbose=True,
                process=Process.sequential
            )

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