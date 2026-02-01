"""
Amazon Bedrock Agents Example for Zero Trust Agent

This example demonstrates how to use the Bedrock Agent Adapter with the actual
AWS boto3 SDK to secure Bedrock agent interactions.

Uses Amazon Bedrock with Zero Trust security validation.

Output: Results are logged and persisted to bedrock_agent_output.json

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

# Import actual AWS boto3 SDK
try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("Warning: boto3 not installed. Running in mock mode.")

# Import Zero Trust Agent components
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor
from zta_agent.integrations.bedrock_agent_adapter import BedrockAgentAdapter

# -- Setup logging --
logging.basicConfig(
    filename="bedrock_agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# -- Load env vars --
load_dotenv()

# Mock token for demonstration
DEMO_TOKEN = "demo_token_12345"


def main():
    """Main execution demonstrating Bedrock Agent with Zero Trust."""
    logger.info("Starting Amazon Bedrock Agent Example with Zero Trust Security")

    # Initialize Zero Trust components
    auth_manager = AuthenticationManager(config={})
    policy_engine = PolicyEngine(config={})
    security_monitor = SecurityMonitor()

    # Initialize Bedrock Agent Adapter
    adapter = BedrockAgentAdapter(auth_manager, policy_engine, security_monitor)

    # Mock authentication
    auth_manager.validate_token = lambda token: {
        "sub": "user_123",
        "identity": "demo_user",
        "permissions": ["read", "write"]
    } if token == DEMO_TOKEN else None

    # Mock policy engine to allow all for demo
    policy_engine.evaluate = lambda context: True

    results = {
        "agent_alias": {},
        "knowledge_base": {},
        "action_group": {},
        "session_attributes": {},
        "model_invocation": {},
        "agent_creation": {},
        "agent_invocation": {},
        "actual_bedrock_call": {}
    }

    # 1. Test Agent Alias Access with Zero Trust
    logger.info("Testing Agent Alias Access...")
    is_allowed = adapter.validate_agent_alias(
        agent_id="agent_001",
        alias_id="alias_prod",
        version="1.0",
        token=DEMO_TOKEN
    )

    results["agent_alias"] = {
        "agent_id": "agent_001",
        "alias_id": "alias_prod",
        "version": "1.0",
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Agent alias access approved")
    else:
        logger.warning("Agent alias access denied")

    # 2. Test Knowledge Base Query with Zero Trust
    logger.info("Testing Knowledge Base Query...")
    query = "What are the security compliance requirements?"
    retrieval_config = {"numberOfResults": 5}

    is_allowed = adapter.validate_knowledge_base_query(
        knowledge_base_id="kb_security_001",
        query=query,
        retrieval_config=retrieval_config,
        token=DEMO_TOKEN
    )

    results["knowledge_base"] = {
        "knowledge_base_id": "kb_security_001",
        "query": query,
        "retrieval_config": retrieval_config,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Knowledge base query approved")
    else:
        logger.warning("Knowledge base query denied")

    # 3. Test Action Group Execution with Zero Trust
    logger.info("Testing Action Group Execution...")
    is_allowed = adapter.validate_action_group(
        action_group_name="SearchAPI",
        api_path="/search/documents",
        http_method="GET",
        parameters={"query": "security policies"},
        token=DEMO_TOKEN
    )

    results["action_group"] = {
        "action_group_name": "SearchAPI",
        "api_path": "/search/documents",
        "http_method": "GET",
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Action group execution approved")
    else:
        logger.warning("Action group execution denied")

    # 4. Test Session Attributes with Zero Trust
    logger.info("Testing Session Attributes...")
    attributes = {
        "user_id": "user_123",
        "session_context": "security_review",
        "permissions": ["read", "search"]
    }

    is_allowed = adapter.validate_session_attributes(
        session_id="session_bedrock_001",
        attributes=attributes,
        operation="update",
        token=DEMO_TOKEN
    )

    results["session_attributes"] = {
        "session_id": "session_bedrock_001",
        "attribute_count": len(attributes),
        "operation": "update",
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Session attributes update approved")
    else:
        logger.warning("Session attributes update denied")

    # 5. Test Model Invocation with Guardrails with Zero Trust
    logger.info("Testing Model Invocation...")
    prompt = "Analyze the security posture of our cloud infrastructure"
    guardrail_config = {
        "enabled": True,
        "version": "1.0",
        "content_policy": "strict"
    }

    is_allowed = adapter.validate_model_invocation(
        model_id="anthropic.claude-3-sonnet",
        prompt=prompt,
        guardrail_config=guardrail_config,
        token=DEMO_TOKEN
    )

    results["model_invocation"] = {
        "model_id": "anthropic.claude-3-sonnet",
        "prompt": prompt,
        "has_guardrails": True,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Model invocation approved")
    else:
        logger.warning("Model invocation denied")

    # 6. Test Agent Creation with Zero Trust
    logger.info("Testing Agent Creation...")
    agent_config = {
        "agentName": "SecurityComplianceAgent",
        "foundationModel": "anthropic.claude-3-sonnet",
        "description": "Agent for security compliance analysis",
        "knowledgeBases": ["kb_security_001"],
        "actionGroups": ["SearchAPI", "ComplianceAPI"]
    }

    is_allowed = adapter.validate_agent_creation(
        agent_config=agent_config,
        token=DEMO_TOKEN
    )

    results["agent_creation"] = {
        "agent_name": agent_config["agentName"],
        "foundation_model": agent_config["foundationModel"],
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Agent creation approved for: {agent_config['agentName']}")
    else:
        logger.warning("Agent creation denied")

    # 7. Test Secure Agent Invocation with Zero Trust
    logger.info("Testing Secure Agent Invocation...")
    invocation_config = {
        "agent_id": "agent_001",
        "alias_id": "alias_prod"
    }

    invocation_result = adapter.secure_agent_invocation(
        invocation_config=invocation_config,
        input_text="Review the latest security audit findings",
        session_id="session_bedrock_002",
        token=DEMO_TOKEN
    )

    results["agent_invocation"] = invocation_result
    logger.info(f"Agent invocation result: {invocation_result}")

    # 8. Actual AWS Bedrock API Call (if credentials available)
    logger.info("Attempting actual Bedrock API call...")
    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_region = os.getenv("AWS_REGION", "us-east-1")

    if BOTO3_AVAILABLE and aws_access_key and aws_secret_key:
        try:
            # Validate the model invocation through Zero Trust adapter
            is_allowed = adapter.validate_model_invocation(
                model_id="anthropic.claude-3-sonnet",
                prompt="Explain Zero Trust security principles",
                guardrail_config={"enabled": True},
                token=DEMO_TOKEN
            )

            if is_allowed:
                # Make actual Bedrock API call
                bedrock_runtime = boto3.client(
                    service_name='bedrock-runtime',
                    region_name=aws_region,
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key
                )

                # Prepare the request body for Claude model
                request_body = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Explain Zero Trust security principles in simple terms"
                        }
                    ]
                }

                response = bedrock_runtime.invoke_model(
                    modelId="anthropic.claude-3-sonnet-20240229-v1:0",
                    body=json.dumps(request_body)
                )

                response_body = json.loads(response['body'].read())

                results["actual_bedrock_call"] = {
                    "status": "success",
                    "model": "anthropic.claude-3-sonnet",
                    "response_preview": response_body.get('content', [{}])[0].get('text', '')[:200] if 'content' in response_body else str(response_body)[:200],
                    "usage": response_body.get('usage', {})
                }
                logger.info("Actual Bedrock API call successful")
            else:
                results["actual_bedrock_call"] = {
                    "status": "denied_by_policy",
                    "reason": "Zero Trust policy denied the invocation"
                }
                logger.warning("Bedrock API call denied by Zero Trust policy")

        except ClientError as e:
            results["actual_bedrock_call"] = {
                "status": "aws_error",
                "error": str(e)
            }
            logger.error(f"Bedrock API call failed: {e}")
        except Exception as e:
            results["actual_bedrock_call"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Bedrock API call failed: {e}")
    else:
        results["actual_bedrock_call"] = {
            "status": "skipped",
            "reason": "AWS credentials not set or boto3 not available"
        }
        logger.info("Skipping actual Bedrock API call - no AWS credentials or boto3 unavailable")

    # Get security context
    security_context = adapter.get_security_context("bedrock_exec_001")
    results["security_context"] = security_context
    logger.info(f"Security Context: {security_context}")

    # Save results
    output_path = "bedrock_agent_output.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Results saved to {output_path}")
    logger.info("Amazon Bedrock Agent Example completed successfully")

    # Print summary
    print("\n" + "="*60)
    print("AMAZON BEDROCK AGENT EXAMPLE - ZERO TRUST SECURITY")
    print("="*60)
    print(json.dumps(results, indent=4))
    print("="*60)


if __name__ == "__main__":
    main()
