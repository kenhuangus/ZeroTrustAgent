"""
IBM watsonx.ai Example for Zero Trust Agent

This example demonstrates how to use the IBM watsonx Adapter with the actual
IBM watsonx.ai SDK to secure model deployments, prompt engineering, and foundation model invocations.

Uses IBM watsonx.ai with Zero Trust security validation.

Output: Results are logged and persisted to ibm_watsonx_output.json

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

# Import actual IBM watsonx SDK
try:
    from ibm_watsonx_ai import APIClient
    from ibm_watsonx_ai.foundation_models import Model
    IBM_SDK_AVAILABLE = True
except ImportError:
    IBM_SDK_AVAILABLE = False
    print("Warning: ibm-watsonx-ai not installed. Running in mock mode.")

# Import Zero Trust Agent components
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor
from zta_agent.integrations.ibm_watsonx_adapter import IBMWatsonXAdapter

# -- Setup logging --
logging.basicConfig(
    filename="ibm_watsonx.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# -- Load env vars --
load_dotenv()

# Mock token for demonstration
DEMO_TOKEN = "demo_token_12345"


def main():
    """Main execution demonstrating IBM watsonx with Zero Trust."""
    logger.info("Starting IBM watsonx.ai Example with Zero Trust Security")

    # Initialize Zero Trust components
    auth_manager = AuthenticationManager(config={})
    policy_engine = PolicyEngine(config={})
    security_monitor = SecurityMonitor()

    # Initialize IBM watsonx Adapter
    adapter = IBMWatsonXAdapter(auth_manager, policy_engine, security_monitor)

    # Mock authentication
    auth_manager.validate_token = lambda token: {
        "sub": "user_123",
        "identity": "demo_user",
        "permissions": ["read", "write"]
    } if token == DEMO_TOKEN else None

    # Mock policy engine to allow all for demo
    policy_engine.evaluate = lambda context: True

    results = {
        "prompt_template": {},
        "model_inference": {},
        "deployment_inference": {},
        "agent_orchestration": {},
        "foundation_model": {},
        "data_governance": {},
        "secure_inference": {},
        "actual_watsonx_call": {}
    }

    # 1. Test Prompt Template with Zero Trust
    logger.info("Testing Prompt Template...")
    template_name = "security-analysis-prompt"
    template_content = "Analyze the security posture of {{system_name}}. Provide detailed analysis."
    template_variables = ["system_name"]

    is_allowed = adapter.validate_prompt_template(
        template_name=template_name,
        template_content=template_content,
        variables=template_variables,
        token=DEMO_TOKEN
    )

    results["prompt_template"] = {
        "template_name": template_name,
        "variable_count": len(template_variables),
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Prompt template approved for: {template_name}")
    else:
        logger.warning("Prompt template denied")

    # 2. Test Model Inference with Zero Trust
    logger.info("Testing Model Inference...")
    model_id = "ibm/granite-13b-instruct-v2"
    input_data = {"prompt": "What are the best practices for securing cloud infrastructure?"}
    deployment_id = "deployment_sec_001"

    is_allowed = adapter.validate_model_inference(
        model_id=model_id,
        input_data=input_data,
        deployment_id=deployment_id,
        token=DEMO_TOKEN
    )

    results["model_inference"] = {
        "model_id": model_id,
        "deployment_id": deployment_id,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Model inference approved")
    else:
        logger.warning("Model inference denied")

    # 3. Test Deployment Inference with Zero Trust
    logger.info("Testing Deployment Inference...")
    inference_params = {
        "temperature": 0.7,
        "max_new_tokens": 500
    }

    is_allowed = adapter.validate_deployment_inference(
        deployment_id=deployment_id,
        inference_params=inference_params,
        token=DEMO_TOKEN
    )

    results["deployment_inference"] = {
        "deployment_id": deployment_id,
        "param_count": len(inference_params),
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info("Deployment inference approved")
    else:
        logger.warning("Deployment inference denied")

    # 4. Test Agent Orchestration with Zero Trust
    logger.info("Testing Agent Orchestration...")
    orchestration_config = {
        "workflow_type": "security_analysis",
        "agents": ["analyzer", "validator", "reporter"]
    }
    agent_count = 3

    is_allowed = adapter.validate_agent_orchestration(
        orchestration_config=orchestration_config,
        agent_count=agent_count,
        token=DEMO_TOKEN
    )

    results["agent_orchestration"] = {
        "workflow_type": orchestration_config["workflow_type"],
        "agent_count": agent_count,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Agent orchestration approved for {agent_count} agents")
    else:
        logger.warning("Agent orchestration denied")

    # 5. Test Foundation Model Access with Zero Trust
    logger.info("Testing Foundation Model Access...")
    access_type = "inference"

    is_allowed = adapter.validate_foundation_model_access(
        model_id=model_id,
        access_type=access_type,
        token=DEMO_TOKEN
    )

    results["foundation_model"] = {
        "model_id": model_id,
        "access_type": access_type,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Foundation model access approved for: {model_id}")
    else:
        logger.warning("Foundation model access denied")

    # 6. Test Data Governance with Zero Trust
    logger.info("Testing Data Governance...")
    data_source = "security_logs_dataset"
    operation = "read"
    compliance_requirements = ["GDPR", "SOX"]

    is_allowed = adapter.validate_data_governance(
        data_source=data_source,
        operation=operation,
        compliance_requirements=compliance_requirements,
        token=DEMO_TOKEN
    )

    results["data_governance"] = {
        "data_source": data_source,
        "operation": operation,
        "compliance": compliance_requirements,
        "allowed": is_allowed
    }

    if is_allowed:
        logger.info(f"Data governance approved for: {data_source}")
    else:
        logger.warning("Data governance denied")

    # 7. Test Secure Inference Execution with Zero Trust
    logger.info("Testing Secure Inference Execution...")
    inference_config = {
        "model_id": model_id,
        "max_new_tokens": 500,
        "temperature": 0.7
    }
    input_text = "Analyze security risks in this cloud configuration"

    inference_result = adapter.secure_inference_execution(
        inference_config=inference_config,
        input_text=input_text,
        deployment_id=deployment_id,
        token=DEMO_TOKEN
    )

    results["secure_inference"] = inference_result
    logger.info(f"Secure inference result: {inference_result}")

    # 8. Register a deployment
    logger.info("Registering deployment...")
    deployment_config = {
        "name": "security-analysis-model",
        "hardware_spec": {"name": "NVIDIA_TESLA_V100"}
    }
    adapter.register_deployment(
        deployment_id=deployment_id,
        model_id=model_id,
        deployment_config=deployment_config,
        token=DEMO_TOKEN
    )

    # 9. Actual IBM watsonx API Call (if credentials available)
    logger.info("Attempting actual watsonx API call...")
    watsonx_api_key = os.getenv("WATSONX_API_KEY")
    watsonx_url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
    watsonx_project_id = os.getenv("WATSONX_PROJECT_ID")

    if IBM_SDK_AVAILABLE and watsonx_api_key and watsonx_project_id:
        try:
            # Validate the model invocation through Zero Trust adapter
            is_allowed = adapter.validate_foundation_model_access(
                model_id="ibm/granite-13b-instruct-v2",
                access_type="inference",
                token=DEMO_TOKEN
            )

            if is_allowed:
                # Make actual watsonx API call
                credentials = {
                    "url": watsonx_url,
                    "apikey": watsonx_api_key
                }

                client = APIClient(credentials)

                model = Model(
                    model_id="ibm/granite-13b-instruct-v2",
                    params={
                        "decoding_method": "greedy",
                        "max_new_tokens": 500,
                        "temperature": 0.7
                    },
                    credentials=credentials,
                    project_id=watsonx_project_id
                )

                prompt = "Explain Zero Trust security principles in simple terms"
                response = model.generate_text(prompt=prompt)

                results["actual_watsonx_call"] = {
                    "status": "success",
                    "model": "ibm/granite-13b-instruct-v2",
                    "response_preview": response[:200] if response else "No response",
                    "project_id": watsonx_project_id
                }
                logger.info("Actual watsonx API call successful")
            else:
                results["actual_watsonx_call"] = {
                    "status": "denied_by_policy",
                    "reason": "Zero Trust policy denied the invocation"
                }
                logger.warning("watsonx API call denied by Zero Trust policy")

        except Exception as e:
            results["actual_watsonx_call"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"watsonx API call failed: {e}")
    else:
        results["actual_watsonx_call"] = {
            "status": "skipped",
            "reason": "WATSONX_API_KEY or WATSONX_PROJECT_ID not set or SDK not available"
        }
        logger.info("Skipping actual watsonx API call - no credentials or SDK unavailable")

    # Get security context
    security_context = adapter.get_security_context("watsonx_exec_001")
    results["security_context"] = security_context
    logger.info(f"Security Context: {security_context}")

    # Save results
    output_path = "ibm_watsonx_output.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Results saved to {output_path}")
    logger.info("IBM watsonx.ai Example completed successfully")

    # Print summary
    print("\n" + "="*60)
    print("IBM WATSONX.AI EXAMPLE - ZERO TRUST SECURITY")
    print("="*60)
    print(json.dumps(results, indent=4))
    print("="*60)


if __name__ == "__main__":
    main()
