"""
Zero Trust Security Agent for AI Frameworks
"""

from .core.auth import AuthenticationManager
from .core.policy import PolicyEngine
from .core.monitor import SecurityMonitor
from .integrations.crewai_adapter import CrewAIAdapter
from .integrations.autogen_adapter import AutoGenAdapter
from .utils.logger import setup_logging, get_logger
from .utils.config import load_config

__version__ = "1.0.0"

logger = get_logger(__name__)

def initialize_agent(config_path: str = "config/policy.yaml"):
    """Initialize the Zero Trust Security Agent with configuration."""
    logger.info("Initializing Zero Trust Security Agent...")
    config = load_config(config_path)
    logger.info("Configuration loaded successfully")

    setup_logging(config.get("logging", {}))
    logger.info("Logging system configured")

    auth_manager = AuthenticationManager(config.get("auth", {}))
    logger.info("Authentication Manager initialized")

    policy_engine = PolicyEngine(config.get("policies", {}))
    logger.info("Policy Engine initialized")

    security_monitor = SecurityMonitor()
    logger.info("Security Monitor initialized")

    components = {
        "auth_manager": auth_manager,
        "policy_engine": policy_engine,
        "security_monitor": security_monitor,
        "crewai_adapter": CrewAIAdapter(auth_manager, policy_engine, security_monitor),
        "autogen_adapter": AutoGenAdapter(auth_manager, policy_engine, security_monitor)
    }

    logger.info("All components initialized successfully")
    return components