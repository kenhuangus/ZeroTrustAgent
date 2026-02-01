"""
IBM watsonx.ai Integration Adapter for Zero Trust Security Agent

This adapter provides comprehensive zero trust security integration for IBM watsonx.ai,
intercepting and validating:
- Prompt template operations
- Model inference and deployment
- Foundation model interactions
- Agent orchestration and multi-agent workflows
- Data governance and compliance
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from typing import Any, Dict, Optional, List, Callable, Union
import functools
import json
from datetime import datetime, timezone

from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor
from ..utils.logger import get_logger

logger = get_logger(__name__)


class IBMWatsonXAdapter:
    """Zero Trust Security Adapter for IBM watsonx.ai"""

    def __init__(self, auth_manager: AuthenticationManager, policy_engine: PolicyEngine, security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor
        self.active_deployments = {}
        self.prompt_templates = {}

    def validate_prompt_template(self, template_name: str, template_content: str, variables: List[str], token: str) -> bool:
        """Validate prompt template creation and modification."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_prompt_template",
                {"template_name": template_name},
                "WARNING"
            )
            return False

        # Validate template content for security risks
        if not self._validate_template_content(template_content):
            self.security_monitor.record_event(
                "suspicious_prompt_template",
                {"template_name": template_name, "creator": claims.get("identity")},
                "WARNING"
            )
            return False

        # Check for prompt injection vulnerabilities
        if self._detect_prompt_injection(template_content):
            self.security_monitor.record_event(
                "prompt_injection_detected",
                {"template_name": template_name, "creator": claims.get("identity")},
                "CRITICAL"
            )
            return False

        context = {
            "action_type": "prompt_template",
            "template_name": template_name,
            "template_length": len(template_content),
            "variable_count": len(variables),
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        if is_allowed:
            self.prompt_templates[template_name] = {
                "content": template_content,
                "variables": variables,
                "created_by": claims.get("identity"),
                "created_at": datetime.now(timezone.utc).isoformat()
            }

        self.security_monitor.record_event(
            "prompt_template_attempt",
            {
                "template_name": template_name,
                "variable_count": len(variables),
                "creator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_model_inference(self, model_id: str, input_data: Dict, deployment_id: Optional[str], token: str) -> bool:
        """Validate model inference requests."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_model_inference",
                {"model_id": model_id},
                "WARNING"
            )
            return False

        # Validate input data
        if not self._validate_inference_input(input_data):
            self.security_monitor.record_event(
                "invalid_inference_input",
                {"model_id": model_id, "input_preview": str(input_data)[:100]},
                "WARNING"
            )
            return False

        context = {
            "action_type": "model_inference",
            "model_id": model_id,
            "deployment_id": deployment_id,
            "input_size": len(str(input_data)),
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "model_inference_attempt",
            {
                "model_id": model_id,
                "deployment_id": deployment_id,
                "executor": claims.get("identity"),
                "input_size": len(str(input_data)),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_deployment_inference(self, deployment_id: str, inference_params: Dict, token: str) -> bool:
        """Validate deployment-based inference with enhanced security."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_deployment_inference",
                {"deployment_id": deployment_id},
                "WARNING"
            )
            return False

        # Check if deployment exists and is active
        if deployment_id not in self.active_deployments:
            self.security_monitor.record_event(
                "inactive_deployment_access",
                {"deployment_id": deployment_id, "user": claims.get("identity")},
                "WARNING"
            )
            return False

        deployment = self.active_deployments[deployment_id]

        # Validate inference parameters
        if not self._validate_inference_params(inference_params):
            self.security_monitor.record_event(
                "invalid_inference_params",
                {"deployment_id": deployment_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "deployment_inference",
            "deployment_id": deployment_id,
            "model_id": deployment.get("model_id"),
            "param_count": len(inference_params),
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "deployment_inference_attempt",
            {
                "deployment_id": deployment_id,
                "model_id": deployment.get("model_id"),
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_agent_orchestration(self, orchestration_config: Dict, agent_count: int, token: str) -> bool:
        """Validate multi-agent orchestration workflows."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_orchestration",
                {"agent_count": agent_count},
                "WARNING"
            )
            return False

        # Limit agent count for resource protection
        if agent_count > 10:
            self.security_monitor.record_event(
                "orchestration_agent_limit_exceeded",
                {"agent_count": agent_count, "user": claims.get("identity")},
                "WARNING"
            )
            return False

        # Validate orchestration configuration
        if not self._validate_orchestration_config(orchestration_config):
            self.security_monitor.record_event(
                "invalid_orchestration_config",
                {"user": claims.get("identity")},
                "WARNING"
            )
            return False

        context = {
            "action_type": "agent_orchestration",
            "agent_count": agent_count,
            "workflow_type": orchestration_config.get("workflow_type"),
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "orchestration_attempt",
            {
                "agent_count": agent_count,
                "workflow_type": orchestration_config.get("workflow_type"),
                "orchestrator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_foundation_model_access(self, model_id: str, access_type: str, token: str) -> bool:
        """Validate access to foundation models."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_model_access",
                {"model_id": model_id, "access_type": access_type},
                "WARNING"
            )
            return False

        # Restrict access to certain models based on permissions
        restricted_models = ["ibm/granite-20b-code-instruct", "ibm-mistral-7b"]
        if model_id in restricted_models and not claims.get("elevated_access"):
            self.security_monitor.record_event(
                "restricted_model_access_denied",
                {"model_id": model_id, "user": claims.get("identity")},
                "WARNING"
            )
            return False

        context = {
            "action_type": "foundation_model_access",
            "model_id": model_id,
            "access_type": access_type,
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "foundation_model_access_attempt",
            {
                "model_id": model_id,
                "access_type": access_type,
                "accessor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_data_governance(self, data_source: str, operation: str, compliance_requirements: List[str], token: str) -> bool:
        """Validate data governance and compliance operations."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_data_governance",
                {"data_source": data_source, "operation": operation},
                "WARNING"
            )
            return False

        # Validate compliance requirements
        valid_compliance = ["GDPR", "HIPAA", "SOX", "PCI-DSS"]
        for req in compliance_requirements:
            if req not in valid_compliance:
                self.security_monitor.record_event(
                    "invalid_compliance_requirement",
                    {"requirement": req, "user": claims.get("identity")},
                    "WARNING"
                )
                return False

        context = {
            "action_type": "data_governance",
            "data_source": data_source,
            "operation": operation,
            "compliance_count": len(compliance_requirements),
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "data_governance_attempt",
            {
                "data_source": data_source,
                "operation": operation,
                "compliance": compliance_requirements,
                "operator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def secure_inference_execution(self, inference_config: Dict, input_text: str, deployment_id: Optional[str] = None, token: str = "") -> Dict:
        """Comprehensive security validation for inference execution."""
        execution_id = f"watsonx_exec_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

        claims = self.auth_manager.validate_token(token)
        if not claims:
            return {
                "allowed": False,
                "reason": "authentication_failed",
                "execution_id": execution_id
            }

        # Validate input text
        if not self._validate_input_text(input_text):
            self.security_monitor.record_event(
                "malicious_inference_input",
                {
                    "execution_id": execution_id,
                    "input_preview": input_text[:100]
                },
                "CRITICAL"
            )
            return {
                "allowed": False,
                "reason": "malicious_input_detected",
                "execution_id": execution_id
            }

        context = {
            "action_type": "inference_execution",
            "model_id": inference_config.get("model_id"),
            "deployment_id": deployment_id,
            "max_new_tokens": inference_config.get("max_new_tokens", 100),
            "temperature": inference_config.get("temperature", 0.7),
            "input_length": len(input_text),
            "execution_id": execution_id,
            "claims": claims,
            "framework": "ibm_watsonx"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "inference_execution_attempt",
            {
                "execution_id": execution_id,
                "model_id": inference_config.get("model_id"),
                "executor": claims.get("identity"),
                "deployment_id": deployment_id,
                "allowed": is_allowed,
                "input_preview": input_text[:100]
            },
            "INFO" if is_allowed else "WARNING"
        )

        return {
            "allowed": is_allowed,
            "execution_id": execution_id,
            "deployment_id": deployment_id,
            "reason": "policy_allowed" if is_allowed else "policy_denied"
        }

    def register_deployment(self, deployment_id: str, model_id: str, deployment_config: Dict, token: str) -> bool:
        """Register a model deployment for tracking."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        self.active_deployments[deployment_id] = {
            "model_id": model_id,
            "config": deployment_config,
            "deployed_by": claims.get("identity"),
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        }

        self.security_monitor.record_event(
            "deployment_registered",
            {
                "deployment_id": deployment_id,
                "model_id": model_id,
                "deployer": claims.get("identity")
            },
            "INFO"
        )
        return True

    def get_security_context(self, execution_id: str) -> Dict:
        """Get security context for a specific execution."""
        return {
            "execution_id": execution_id,
            "active_deployments": len(self.active_deployments),
            "prompt_templates": len(self.prompt_templates),
            "adapter_version": "1.0.0",
            "framework": "ibm_watsonx"
        }

    def _validate_template_content(self, content: str) -> bool:
        """Validate prompt template content."""
        if not content or len(content) > 10000:
            return False
        return True

    def _detect_prompt_injection(self, content: str) -> bool:
        """Detect potential prompt injection attacks."""
        injection_patterns = [
            "ignore previous instructions",
            "disregard all prior",
            "new system prompt:",
            "you are now",
            "override security",
            "bypass restrictions"
        ]
        content_lower = content.lower()
        for pattern in injection_patterns:
            if pattern in content_lower:
                return True
        return False

    def _validate_inference_input(self, input_data: Dict) -> bool:
        """Validate model inference input."""
        if not input_data:
            return False
        input_str = str(input_data).lower()
        suspicious_patterns = ["rm -rf", "drop table", "<script>", "eval("]
        for pattern in suspicious_patterns:
            if pattern in input_str:
                return False
        return True

    def _validate_inference_params(self, params: Dict) -> bool:
        """Validate inference parameters."""
        # Check temperature range
        if "temperature" in params:
            temp = params["temperature"]
            if not isinstance(temp, (int, float)) or temp < 0 or temp > 2:
                return False
        # Check max tokens
        if "max_new_tokens" in params:
            tokens = params["max_new_tokens"]
            if not isinstance(tokens, int) or tokens < 1 or tokens > 4096:
                return False
        return True

    def _validate_orchestration_config(self, config: Dict) -> bool:
        """Validate orchestration configuration."""
        required_fields = ["workflow_type", "agents"]
        for field in required_fields:
            if field not in config:
                return False
        return True

    def _validate_input_text(self, text: str) -> bool:
        """Validate input text for security."""
        if not text or len(text) > 20000:
            return False
        malicious_patterns = [
            "ignore previous instructions",
            "system: you are now",
            "<script", "javascript:"
        ]
        for pattern in malicious_patterns:
            if pattern in text.lower():
                return False
        return True
