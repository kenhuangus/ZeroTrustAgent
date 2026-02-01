"""
Anthropic Claude Agent Example for Zero Trust Agent

This example demonstrates how to use the Claude Agent Adapter with the actual
Anthropic Claude SDK to secure tool use, computer use, and multi-turn conversations.

Uses Anthropic Claude API with Zero Trust security validation.

Output: Results are logged and persisted to claude_agent_output.json

# @Author: Zero Trust Agent Team
# Date: February 2025
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import logging
from typing import Dict, Any, List
from dotenv import load_dotenv

# Import actual Anthropic SDK
try:
    from anthropic import Anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False
    print("Warning: anthropic SDK not installed. Running in mock mode.")

# Import Zero Trust Agent components
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor
from zta_agent.integrations.claude_agent_adapter import ClaudeAgentAdapter

# -- Setup logging --
logging.basicConfig(
    filename="claude_agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# -- Load env vars --
load_dotenv()

# Mock token for demonstration
DEMO_TOKEN = "demo_token_12345"


def get_weather(location: str) -> str:
    """Mock tool to get weather information."""
    return f"Weather in {location}: Sunny, 72°F"


def search_documents(query: str) -> List[Dict]:
    """Mock tool to search documents."""
    return [
        {"title": f"Document about {query}", "content": f"Content related to {query}"}
    ]


def main():
    """Main execution demonstrating Claude Agent with Zero Trust."""
    logger.info("Starting Anthropic Claude Agent Example with Zero Trust Security")

    # Initialize Zero Trust components
    auth_manager = AuthenticationManager(config={})
    policy_engine = PolicyEngine(config={})
    security_monitor = SecurityMonitor()

    # Initialize Claude Agent Adapter
    adapter = ClaudeAgentAdapter(auth_manager, policy_engine, security_monitor)

    # Mock authentication
    auth_manager.validate_token = lambda token: {
        "sub": "user_123",
        "identity": "demo_user",
        "permissions": ["read", "write"]
    } if token == DEMO_TOKEN else None

    # Mock policy engine to allow all for demo
    policy_engine.evaluate = lambda context: True

    results = {
        "tool_use": {},
        "computer_use": {},
        "message_creation": {},
        "secure_conversation": {},
        "extended_thinking": {},
        "artifact_creation": {},
        "agent_session": {},
        "actual_claude_call": {}
    }

    # 1. Test Tool Use with Zero Trust
    logger.info("Testing Tool Use...")
    tool_name = "get_weather"
    tool_input = {"location": "San Francisco"}

    is_allowed = adapter.validate_tool_use(
        tool_name=tool_name,
        tool_input=tool_input,
        agent_id="claude_agent_001",
        token=DEMO_TOKEN
    )

    results["tool_use"] = {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "allowed": is_allowed
    }

    if is_allowed:
        result = get_weather(**tool_input)
        results["tool_use"]["result"] = result
        logger.info(f"Tool use approved. Result: {result}")
    else:
        logger.warning("Tool use denied by policy")

    # 2. Test Computer Use with Zero Trust
    logger.info("Testing Computer Use...")
    operation = "screenshot"
    params = {"x": 100, "y": 200}

    is_allowed = adapter.validate_computer_use_operation(
        operation=operation,
        params=params,
        agent_id="claude_agent_001",
        token=DEMO_TOKEN
    )

    results["computer_use"] = {
        "operation": operation,
        "params": params,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Computer use approved for operation: {operation}")
    else:
        logger.warning("Computer use denied by policy")

    # 3. Test Message Creation with Zero Trust
    logger.info("Testing Message Creation...")
    message_config = {
        "role": "user",
        "content": "Show me the failed login attempts from last week",
        "has_tool_calls": False,
        "has_tool_results": False
    }

    is_allowed = adapter.validate_message_creation(
        message_config=message_config,
        token=DEMO_TOKEN
    )

    results["message_creation"] = {
        "message_role": message_config["role"],
        "content_preview": message_config["content"][:50],
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Message creation approved")
    else:
        logger.warning("Message creation denied")

    # 4. Test Secure Conversation Turn with Zero Trust
    logger.info("Testing Secure Conversation Turn...")
    conversation_config = {
        "model": "claude-3-sonnet-20240229",
        "max_tokens": 4096,
        "temperature": 0.7,
        "tools": [
            {"type": "function", "name": "get_weather"},
            {"type": "function", "name": "search_documents"}
        ],
        "enable_computer_use": True
    }

    conversation_result = adapter.secure_conversation_turn(
        conversation_config=conversation_config,
        user_input="Start a secure conversation for security analysis",
        session_id="conv_claude_001",
        token=DEMO_TOKEN
    )

    results["secure_conversation"] = conversation_result
    logger.info(f"Secure conversation result: {conversation_result}")

    # 5. Test Extended Thinking with Zero Trust
    logger.info("Testing Extended Thinking...")
    thinking_config = {
        "budget_tokens": 4000,
        "enabled": True
    }

    is_allowed = adapter.validate_extended_thinking(
        thinking_config=thinking_config,
        agent_id="claude_agent_001",
        token=DEMO_TOKEN
    )

    results["extended_thinking"] = {
        "thinking_budget": thinking_config["budget_tokens"],
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Extended thinking approved")
    else:
        logger.warning("Extended thinking denied")

    # 6. Test Artifact Creation with Zero Trust
    logger.info("Testing Artifact Creation...")
    artifact_type = "code"
    artifact_content = {
        "language": "python",
        "code": "def analyze_security_logs(logs): return logs"
    }

    is_allowed = adapter.validate_artifact_creation(
        artifact_type=artifact_type,
        artifact_content=artifact_content,
        agent_id="claude_agent_001",
        token=DEMO_TOKEN
    )

    results["artifact_creation"] = {
        "artifact_type": artifact_type,
        "content_size": len(str(artifact_content)),
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Artifact creation approved")
    else:
        logger.warning("Artifact creation denied")

    # 7. Test Agent Session with Zero Trust
    logger.info("Testing Agent Session...")
    session_result = adapter.validate_agent_session(
        session_id="session_claude_001",
        operation="create",
        session_data={"user_id": "user_123", "context": "security_analysis"},
        token=DEMO_TOKEN
    )

    results["agent_session"] = {
        "session_id": "session_claude_001",
        "operation": "create",
        "allowed": session_result
    }

    if session_result:
        logger.info("Agent session operation approved")
    else:
        logger.warning("Agent session operation denied")

    # 8. Actual Anthropic Claude API Call (if API key available)
    logger.info("Attempting actual Claude API call...")
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if ANTHROPIC_SDK_AVAILABLE and api_key:
        try:
            # Validate the model invocation through Zero Trust adapter
            model_config = {
                "model": "claude-3-sonnet-20240229",
                "max_tokens": 1024,
                "system": "You are a security analyst."
            }

            is_allowed = adapter.validate_message_creation(
                message_config={
                    "role": "user",
                    "content": "Explain Zero Trust security principles",
                    "has_tool_calls": False,
                    "has_tool_results": False
                },
                token=DEMO_TOKEN
            )

            if is_allowed:
                # Make actual Claude API call
                client = Anthropic(api_key=api_key)
                response = client.messages.create(
                    model="claude-3-sonnet-20240229",
                    max_tokens=1024,
                    system="You are a security analyst.",
                    messages=[
                        {"role": "user", "content": "Explain Zero Trust security principles in simple terms"}
                    ]
                )

                results["actual_claude_call"] = {
                    "status": "success",
                    "model": "claude-3-sonnet-20240229",
                    "response_preview": response.content[0].text[:200] if response.content else "No content",
                    "usage": {
                        "input_tokens": response.usage.input_tokens if hasattr(response, 'usage') else None,
                        "output_tokens": response.usage.output_tokens if hasattr(response, 'usage') else None
                    }
                }
                logger.info("Actual Claude API call successful")
            else:
                results["actual_claude_call"] = {
                    "status": "denied_by_policy",
                    "reason": "Zero Trust policy denied the invocation"
                }
                logger.warning("Claude API call denied by Zero Trust policy")

        except Exception as e:
            results["actual_claude_call"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Claude API call failed: {e}")
    else:
        results["actual_claude_call"] = {
            "status": "skipped",
            "reason": "ANTHROPIC_API_KEY not set or SDK not available"
        }
        logger.info("Skipping actual Claude API call - no API key or SDK unavailable")

    # Get security context
    security_context = adapter.get_security_context("claude_exec_001")
    results["security_context"] = security_context
    logger.info(f"Security Context: {security_context}")

    # Save results
    output_path = "claude_agent_output.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Results saved to {output_path}")
    logger.info("Anthropic Claude Agent Example completed successfully")

    # Print summary
    print("\n" + "="*60)
    print("ANTHROPIC CLAUDE AGENT EXAMPLE - ZERO TRUST SECURITY")
    print("="*60)
    print(json.dumps(results, indent=4))
    print("="*60)


if __name__ == "__main__":
    main()
