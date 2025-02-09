"""
CrewAI Integration Example with Zero Trust Security Agent
"""

import os
import logging
import sys
import time
import requests
from typing import Any, List, Dict, Optional
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process

from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool

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

class TogetherLLM:
    """Custom LLM class for Together AI integration."""

    def __init__(self, api_key: str, model: str = "mistralai/Mistral-7B-Instruct-v0.1"):
        self.api_key = api_key
        self.model = model
        self.api_base = "https://api.together.xyz/inference"

    def generate(self, messages):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # Convert CrewAI messages to Together AI format
        prompt = self._convert_messages_to_prompt(messages)

        payload = {
            "model": self.model,
            "prompt": prompt,
            "max_tokens": 512,
            "temperature": 0.7,
        }

        try:
            response = requests.post(
                self.api_base,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            return response.json()["output"]["choices"][0]["text"]
        except Exception as e:
            logger.error(f"Together AI API call failed: {str(e)}")
            raise

    def _convert_messages_to_prompt(self, messages):
        """Convert CrewAI message format to Together AI prompt format."""
        prompt_parts = []
        for message in messages:
            if message["role"] == "system":
                prompt_parts.append(f"System: {message['content']}\n")
            elif message["role"] == "user":
                prompt_parts.append(f"Human: {message['content']}\n")
            elif message["role"] == "assistant":
                prompt_parts.append(f"Assistant: {message['content']}\n")
        return "".join(prompt_parts)

@retry(
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
    reraise=True
)
def create_secure_agent(agent_id: str, token: str) -> Agent:
    """Create a secure agent with ZTA validation."""
    logger.info(f"Creating secure agent: {agent_id}")

    try:
        # Initialize tools
        tools = [SecureSearchTool()]

        together_api_key = os.environ.get('TOGETHER_API_KEY')
        if not together_api_key:
            raise ValueError("Together API key not found")

        # Create custom Together AI LLM instance
        llm = TogetherLLM(api_key=together_api_key)

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
                expected_output="A comprehensive analysis and detailed report",
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