"""
CrewAI Integration Example with Zero Trust Security Agent
"""

from crewai import Agent, Task, Crew
from zta_agent import initialize_agent
import logging
import sys

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

    # Define the agent with proper role and tools
    agent = Agent(
        role="Security Researcher",
        goal="Research and analyze security practices securely and efficiently",
        backstory="An AI security researcher with expertise in analyzing security practices and implementing secure solutions",
        verbose=True,
        allow_delegation=False
    )

    # Store the original work method
    original_work = agent.work

    def secure_work(task: Task) -> str:
        """Secure wrapper around agent's work method."""
        logger.info(f"Agent {agent_id} attempting to execute task: {task.description}")

        # Validate the task execution
        task_context = {
            'type': 'research' if 'research' in task.description.lower() else 'analyze',
            'description': task.description
        }

        secured_task = crewai_adapter.secure_task_execution(
            task=task_context,
            agent_id=agent_id,
            token=token
        )

        if secured_task:
            logger.info(f"Task execution approved for agent {agent_id}")
            try:
                result = original_work(task)
                logger.info(f"Task execution completed for agent {agent_id}")
                return result
            except Exception as e:
                logger.error(f"Error executing task: {str(e)}")
                raise
        else:
            logger.warning(f"Task execution denied for agent {agent_id}")
            return "Access denied: Security policy violation"

    # Replace the work method with our secure version
    agent.work = secure_work
    return agent

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

        # Create tasks
        research_task = Task(
            description="Research AI security best practices",
            agent=researcher
        )

        analysis_task = Task(
            description="Analyze security findings and create report",
            agent=analyst
        )

        # Create and run crew
        logger.info("Creating and starting crew...")
        crew = Crew(
            agents=[researcher, analyst],
            tasks=[research_task, analysis_task],
            verbose=True
        )

        result = crew.kickoff()
        logger.info("Crew execution completed")
        print("Crew execution result:", result)

    except Exception as e:
        logger.error(f"Error in CrewAI integration demo: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()