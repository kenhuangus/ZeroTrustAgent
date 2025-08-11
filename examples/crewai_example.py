import os
import logging
import sys
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, LLM
from zta_agent import initialize_agent
from zta_agent.tools.search_tool import SecureSearchTool

# Reconfigure stdout and stderr to use UTF-8 if available.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Disable logging exceptions so Unicode errors are not printed.
logging.raiseExceptions = False

# Determine whether stdout supports emoji.
USE_EMOJI = True
if sys.stdout.encoding is None or "utf-8" not in sys.stdout.encoding.lower():
    USE_EMOJI = False

def safe_emoji(text):
    """
    Replace emoji characters with ASCII fallbacks if emoji output is not supported.
    """
    if not USE_EMOJI:
        replacements = {
            "🔑": "[KEY]",
            "🤖": "[ASSISTANT]",
            "👤": "[USER]",
            "✅": "[ALLOWED]",
            "🚨": "[LLM ERROR]",
            "🚫": "[DENIED]",
            "🔥": "[ERROR]",
            "🔧": "[INIT]",
            "📨": "[SEND]",
            "📵": "[DENY]",
            "📝": "[MONITOR]",
            "🔒": "[LOCKED]"
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
    return text

# Custom logging handler that catches UnicodeEncodeError and does nothing.
class UnicodeSafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except UnicodeEncodeError:
            # Do nothing if encoding fails.
            pass

# Reconfigure logging to use the custom handler.
handler = UnicodeSafeStreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger = logging.getLogger(__name__)
logger.handlers = []  # Clear any existing handlers.
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load environment variables.
load_dotenv()

# Retrieve API key.
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")

# Initialize ZTA components.
logger.info(safe_emoji("Initializing Zero Trust Security Agent components..."))
zta_components = initialize_agent()
crewai_adapter = zta_components["crewai_adapter"]
auth_manager = zta_components["auth_manager"]

@retry(
    wait=wait_exponential(multiplier=1, min=4, max=10),
    stop=stop_after_attempt(2),
    reraise=True
)
def create_secure_agent(agent_id: str, llm: LLM) -> Agent:
    """
    Create a secure agent with ZTA validation using the provided LLM instance.
    """
    logger.info(safe_emoji(f"Creating secure agent: {agent_id}"))
    try:
        # Initialize security tools.
        tools = [SecureSearchTool()]

        # Configure the secure agent using the passed LLM instance.
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

        agent = Agent(**agent_config)
        logger.info(safe_emoji(f"Successfully created agent: {agent_id}"))
        return agent

    except Exception as e:
        logger.error(safe_emoji(f"Error creating agent {agent_id}: {str(e)}"))
        raise

def create_secure_task(description: str, agent: Agent, expected_output: str = "") -> Task:
    """
    Create a secure task for an agent.
    """
    try:
        task = Task(
            description=description,
            agent=agent,
            expected_output=expected_output
        )
        logger.info(safe_emoji(f"Successfully created secure task for agent with role: {agent.role}"))
        return task
    except Exception as e:
        logger.error(safe_emoji(f"Error creating secure task for agent with role {agent.role}: {str(e)}"))
        raise

def main():
    # Create a single LLM instance to be used across all agents.
    llm = LLM(
        model="together_ai/meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        base_url="https://api.together.xyz",
        api_key=TOGETHER_API_KEY
    )
    
    # Create two agents:
    #   - allowed_agent with identity "research_agent" (allowed by policy).
    #   - denied_agent with identity "denied_agent" (which will be rejected by policy).
    allowed_agent = create_secure_agent("research_agent", llm)
    denied_agent = create_secure_agent("denied_agent", llm)
    
    # Authenticate both agents with their credentials.
    allowed_credentials = {"identity": "research_agent", "secret": "research_secret"}
    denied_credentials = {"identity": "denied_agent", "secret": "denied_secret"}
    allowed_token = auth_manager.authenticate(allowed_credentials)
    denied_token = auth_manager.authenticate(denied_credentials)
    
    if allowed_token:
        logger.info(safe_emoji(f"🔑 Authentication successful for research_agent: {allowed_token}"))
    else:
        logger.error(safe_emoji("🔑 Authentication failed for research_agent"))
    if denied_token:
        logger.info(safe_emoji(f"🔑 Authentication successful for denied_agent: {denied_token}"))
    else:
        logger.error(safe_emoji("🔑 Authentication failed for denied_agent"))
    
    # Validate action policy for both agents.
    dummy_action = {"type": "execute_task", "resource": "secure_operation"}
    allowed_is_allowed = crewai_adapter.validate_agent_action("research_agent", dummy_action, allowed_token)
    denied_is_allowed = crewai_adapter.validate_agent_action("denied_agent", dummy_action, denied_token)
    
    if allowed_is_allowed:
        logger.info(safe_emoji("🔒 Policy Decision: research_agent allowed to perform the action"))
    else:
        logger.info(safe_emoji("🔒 Policy Decision: research_agent denied performing the action"))
    
    if denied_is_allowed:
        logger.info(safe_emoji("🔒 Policy Decision: denied_agent allowed to perform the action"))
    else:
        logger.info(safe_emoji("🔒 Policy Decision: denied_agent denied performing the action. Halting execution for denied_agent."))
    
    # Create a task for the allowed agent only.
    research_task = create_secure_task(
        description="Research the latest developments in artificial intelligence",
        agent=allowed_agent,
        expected_output="A comprehensive analysis of recent AI developments and breakthroughs"
    )
    
    # For the denied agent, tasks are not created due to the policy denial.
    tasks_for_denied = []
    if denied_is_allowed:
        tasks_for_denied.append(create_secure_task(
            description="Task for denied_agent, should not run",
            agent=denied_agent,
            expected_output="Should not be executed"
        ))
    else:
        logger.info(safe_emoji("No tasks created for denied_agent due to policy denial."))
    
    # Create and run the crew for the allowed agent.
    crew_allowed = Crew(
        agents=[allowed_agent],
        tasks=[research_task],
        verbose=True
    )
    
    try:
        result_allowed = crew_allowed.kickoff()
        print("\nFinal Result for allowed agent:")
        print(result_allowed)
    except Exception as e:
        logger.error(safe_emoji(f"Error running allowed crew: {str(e)}"))
    
    # Optionally, if tasks were present for the denied agent, execute them.
    if tasks_for_denied:
        crew_denied = Crew(
            agents=[denied_agent],
            tasks=tasks_for_denied,
            verbose=True
        )
        try:
            result_denied = crew_denied.kickoff()
            logger.info(safe_emoji("Denied agent crew execution result: " + str(result_denied)))
        except Exception as e:
            logger.error(safe_emoji(f"Error running denied crew: {str(e)}"))
    else:
        logger.info(safe_emoji("Denied agent did not execute any tasks due to policy denial."))

if __name__ == "__main__":
    main()