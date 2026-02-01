"""
Google Agent SDK (Gemini) Example for Zero Trust Agent

This example demonstrates how to use the Google Agent Adapter with the actual
Google Generative AI SDK to secure Gemini model interactions.

Uses Google Gemini API with Zero Trust security validation.

Output: Results are logged and persisted to google_agent_output.json

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

# Import actual Google Generative AI SDK
try:
    import google.generativeai as genai
    from google.generativeai.types import HarmCategory, HarmBlockThreshold
    GOOGLE_SDK_AVAILABLE = True
except ImportError:
    GOOGLE_SDK_AVAILABLE = False
    print("Warning: google-generativeai not installed. Running in mock mode.")

# Import Zero Trust Agent components
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor
from zta_agent.integrations.google_agent_adapter import GoogleAgentAdapter

# -- Setup logging --
logging.basicConfig(
    filename="google_agent.log",
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
    """Main execution demonstrating Google Agent SDK with Zero Trust."""
    logger.info("Starting Google Agent SDK Example with Zero Trust Security")

    # Initialize Zero Trust components
    auth_manager = AuthenticationManager(config={})
    policy_engine = PolicyEngine(config={})
    security_monitor = SecurityMonitor()

    # Initialize Google Agent Adapter
    adapter = GoogleAgentAdapter(auth_manager, policy_engine, security_monitor)

    # Mock authentication
    auth_manager.validate_token = lambda token: {
        "sub": "user_123",
        "identity": "demo_user",
        "permissions": ["read", "write"]
    } if token == DEMO_TOKEN else None

    # Mock policy engine to allow all for demo
    policy_engine.evaluate = lambda context: True

    results = {
        "function_calling": {},
        "grounding": {},
        "chat_session": {},
        "deployment": {},
        "actual_gemini_call": {}
    }

    # 1. Test Function Calling with Zero Trust
    logger.info("Testing Function Calling...")
    function_args = {"location": "New York"}

    is_allowed = adapter.validate_function_calling(
        function_name="get_weather",
        function_args=function_args,
        agent_id="google_agent_001",
        token=DEMO_TOKEN
    )

    results["function_calling"] = {
        "function": "get_weather",
        "args": function_args,
        "allowed": is_allowed
    }

    if is_allowed:
        result = get_weather(**function_args)
        results["function_calling"]["result"] = result
        logger.info(f"Function call approved. Result: {result}")
    else:
        logger.warning("Function call denied by policy")

    # 2. Test Grounding/Retrieval with Zero Trust
    logger.info("Testing Grounding...")
    query = "What are the security policies for data access?"
    sources = ["https://company.com/policies", "https://company.com/security"]

    is_allowed = adapter.validate_grounding(
        query=query,
        sources=sources,
        agent_id="google_agent_001",
        token=DEMO_TOKEN
    )

    results["grounding"] = {
        "query": query,
        "sources": sources,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Grounding approved for query: {query[:50]}...")
    else:
        logger.warning("Grounding denied by policy")

    # 3. Test Multi-turn Chat with Zero Trust
    logger.info("Testing Multi-turn Chat...")
    chat_history = [
        {"role": "user", "content": "Hello, I need help with security policies"},
        {"role": "assistant", "content": "I can help you with security policies. What do you need?"}
    ]
    new_message = "How do I request access to sensitive data?"

    is_allowed = adapter.validate_multi_turn_chat(
        chat_history=chat_history,
        new_message=new_message,
        agent_id="google_agent_001",
        token=DEMO_TOKEN
    )

    results["chat_session"] = {
        "history_length": len(chat_history),
        "new_message": new_message,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Chat message approved")
    else:
        logger.warning("Chat message denied by policy")

    # 4. Test Secure Chat Session
    logger.info("Testing Secure Chat Session...")
    session_config = {
        "model": "gemini-pro",
        "temperature": 0.7,
        "tools": ["get_weather", "search_documents"],
        "enable_grounding": True
    }

    session_result = adapter.secure_chat_session(
        session_config=session_config,
        initial_message="Start a secure chat session for security policy questions",
        session_id="session_google_001",
        token=DEMO_TOKEN
    )

    results["chat_session"]["secure_session"] = session_result
    logger.info(f"Secure session result: {session_result}")

    # 5. Test Agent Deployment (Vertex AI) with Zero Trust
    logger.info("Testing Agent Deployment...")
    deployment_config = {
        "display_name": "ZeroTrustSecurityAgent",
        "model": "gemini-pro",
        "description": "Agent for handling security policy queries"
    }

    is_allowed = adapter.validate_agent_deployment(
        deployment_config=deployment_config,
        project_id="my-gcp-project-123",
        token=DEMO_TOKEN
    )

    results["deployment"] = {
        "config": deployment_config,
        "project_id": "my-gcp-project-123",
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Deployment approved for: {deployment_config['display_name']}")
    else:
        logger.warning("Deployment denied by policy")

    # 6. Actual Google Gemini API Call (if API key available)
    logger.info("Attempting actual Gemini API call...")
    api_key = os.getenv("GOOGLE_API_KEY")

    if GOOGLE_SDK_AVAILABLE and api_key:
        try:
            # Configure Gemini with Zero Trust validation
            genai.configure(api_key=api_key)

            # Validate the model invocation through Zero Trust adapter
            model_config = {
                "model": "gemini-pro",
                "temperature": 0.7,
                "max_output_tokens": 1024
            }

            is_allowed = adapter.validate_model_invocation(
                model_config=model_config,
                prompt="Explain Zero Trust security principles in simple terms",
                agent_id="google_agent_001",
                token=DEMO_TOKEN
            )

            if is_allowed:
                # Make actual Gemini API call
                model = genai.GenerativeModel('gemini-pro')
                response = model.generate_content(
                    "Explain Zero Trust security principles in simple terms",
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.7,
                        max_output_tokens=1024
                    ),
                    safety_settings={
                        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                    }
                )

                results["actual_gemini_call"] = {
                    "status": "success",
                    "model": "gemini-pro",
                    "response_preview": response.text[:200] if hasattr(response, 'text') else "No text response",
                    "safety_ratings": [
                        {"category": str(r.category), "probability": str(r.probability)}
                        for r in (response.prompt_feedback.safety_ratings if hasattr(response, 'prompt_feedback') else [])
                    ]
                }
                logger.info("Actual Gemini API call successful")
            else:
                results["actual_gemini_call"] = {
                    "status": "denied_by_policy",
                    "reason": "Zero Trust policy denied the invocation"
                }
                logger.warning("Gemini API call denied by Zero Trust policy")

        except Exception as e:
            results["actual_gemini_call"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Gemini API call failed: {e}")
    else:
        results["actual_gemini_call"] = {
            "status": "skipped",
            "reason": "GOOGLE_API_KEY not set or SDK not available"
        }
        logger.info("Skipping actual Gemini API call - no API key or SDK unavailable")

    # Get security context
    security_context = adapter.get_security_context("google_exec_001")
    results["security_context"] = security_context
    logger.info(f"Security Context: {security_context}")

    # Save results
    output_path = "google_agent_output.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Results saved to {output_path}")
    logger.info("Google Agent SDK Example completed successfully")

    # Print summary
    print("\n" + "="*60)
    print("GOOGLE AGENT SDK EXAMPLE - ZERO TRUST SECURITY")
    print("="*60)
    print(json.dumps(results, indent=4))
    print("="*60)


if __name__ == "__main__":
    main()
