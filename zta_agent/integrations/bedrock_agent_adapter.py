"""
Amazon Bedrock Agents Integration Adapter for Zero Trust Security Agent

This adapter provides comprehensive zero trust security integration for Amazon Bedrock Agents,
intercepting and validating:
- Agent alias and version management
- Knowledge base queries and retrieval
- Action group execution
- Session attribute management
- Model invocation and guardrails
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


class BedrockAgentAdapter:
    """Zero Trust Security Adapter for Amazon Bedrock Agents"""

    def __init__(self, auth_manager: AuthenticationManager, policy_engine: PolicyEngine, security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor
        self.active_agents = {}
        self.knowledge_base_access_log = {}

    def validate_agent_alias(self, agent_id: str, alias_id: str, version: str, token: str) -> bool:
        """Validate agent alias and version access."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_alias_access",
                {"agent_id": agent_id, "alias_id": alias_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "agent_alias_access",
            "agent_id": agent_id,
            "alias_id": alias_id,
            "version": version,
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_alias_access_attempt",
            {
                "agent_id": agent_id,
                "alias_id": alias_id,
                "version": version,
                "accessor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_knowledge_base_query(self, knowledge_base_id: str, query: str, retrieval_config: Dict, token: str) -> bool:
        """Validate knowledge base queries with security checks."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_kb_query",
                {"knowledge_base_id": knowledge_base_id},
                "WARNING"
            )
            return False

        # Validate query for security risks
        if not self._validate_kb_query(query):
            self.security_monitor.record_event(
                "suspicious_kb_query",
                {"knowledge_base_id": knowledge_base_id, "query_preview": query[:100]},
                "WARNING"
            )
            return False

        context = {
            "action_type": "knowledge_base_query",
            "knowledge_base_id": knowledge_base_id,
            "query_length": len(query),
            "retrieval_count": retrieval_config.get("numberOfResults", 5),
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        # Log access for audit
        access_id = f"kb_access_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"
        self.knowledge_base_access_log[access_id] = {
            "knowledge_base_id": knowledge_base_id,
            "query": query[:200],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "accessor": claims.get("identity"),
            "allowed": is_allowed
        }

        self.security_monitor.record_event(
            "knowledge_base_query_attempt",
            {
                "access_id": access_id,
                "knowledge_base_id": knowledge_base_id,
                "query_preview": query[:100],
                "accessor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_action_group(self, action_group_name: str, api_path: str, http_method: str, parameters: Dict, token: str) -> bool:
        """Validate action group API execution."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_action_group",
                {"action_group": action_group_name, "api_path": api_path},
                "WARNING"
            )
            return False

        # Validate parameters for security
        if not self._validate_action_parameters(parameters):
            self.security_monitor.record_event(
                "suspicious_action_parameters",
                {"action_group": action_group_name, "api_path": api_path},
                "WARNING"
            )
            return False

        # Check for dangerous HTTP methods
        dangerous_methods = ["DELETE", "PUT", "PATCH"]
        if http_method.upper() in dangerous_methods:
            self.security_monitor.record_event(
                "dangerous_http_method_attempt",
                {
                    "action_group": action_group_name,
                    "api_path": api_path,
                    "http_method": http_method,
                    "user": claims.get("identity")
                },
                "WARNING"
            )

        context = {
            "action_type": "action_group_execution",
            "action_group_name": action_group_name,
            "api_path": api_path,
            "http_method": http_method,
            "param_count": len(parameters),
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "action_group_attempt",
            {
                "action_group": action_group_name,
                "api_path": api_path,
                "http_method": http_method,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_session_attributes(self, session_id: str, attributes: Dict, operation: str, token: str) -> bool:
        """Validate session attribute operations."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_session_operation",
                {"session_id": session_id, "operation": operation},
                "WARNING"
            )
            return False

        # Validate attribute size for DoS prevention
        attr_size = len(json.dumps(attributes))
        if attr_size > 100000:  # 100KB limit
            self.security_monitor.record_event(
                "session_attributes_too_large",
                {"session_id": session_id, "size": attr_size},
                "WARNING"
            )
            return False

        context = {
            "action_type": "session_attributes",
            "session_id": session_id,
            "operation": operation,
            "attribute_count": len(attributes),
            "attribute_size": attr_size,
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "session_attributes_attempt",
            {
                "session_id": session_id,
                "operation": operation,
                "attribute_count": len(attributes),
                "operator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_model_invocation(self, model_id: str, prompt: str, guardrail_config: Optional[Dict], token: str) -> bool:
        """Validate model invocation with guardrails."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_model_invocation",
                {"model_id": model_id},
                "WARNING"
            )
            return False

        # Validate prompt
        if not self._validate_prompt(prompt):
            self.security_monitor.record_event(
                "malicious_prompt_detected",
                {"model_id": model_id, "prompt_preview": prompt[:100]},
                "CRITICAL"
            )
            return False

        # Check guardrail configuration
        if guardrail_config and not self._validate_guardrail_config(guardrail_config):
            self.security_monitor.record_event(
                "invalid_guardrail_config",
                {"model_id": model_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "model_invocation",
            "model_id": model_id,
            "prompt_length": len(prompt),
            "has_guardrails": bool(guardrail_config),
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "model_invocation_attempt",
            {
                "model_id": model_id,
                "prompt_preview": prompt[:100],
                "has_guardrails": bool(guardrail_config),
                "invoker": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_agent_creation(self, agent_config: Dict, token: str) -> bool:
        """Validate new agent creation."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_creation",
                {},
                "WARNING"
            )
            return False

        # Validate configuration
        if not self._validate_agent_config(agent_config):
            self.security_monitor.record_event(
                "invalid_agent_config",
                {"creator": claims.get("identity")},
                "WARNING"
            )
            return False

        context = {
            "action_type": "agent_creation",
            "agent_name": agent_config.get("agentName"),
            "foundation_model": agent_config.get("foundationModel"),
            "has_knowledge_bases": bool(agent_config.get("knowledgeBases")),
            "has_action_groups": bool(agent_config.get("actionGroups")),
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        if is_allowed:
            agent_id = f"agent_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            self.active_agents[agent_id] = {
                "name": agent_config.get("agentName"),
                "model": agent_config.get("foundationModel"),
                "created_by": claims.get("identity"),
                "created_at": datetime.now(timezone.utc).isoformat()
            }

        self.security_monitor.record_event(
            "agent_creation_attempt",
            {
                "agent_name": agent_config.get("agentName"),
                "foundation_model": agent_config.get("foundationModel"),
                "creator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def secure_agent_invocation(self, invocation_config: Dict, input_text: str, session_id: Optional[str] = None, token: str = "") -> Dict:
        """Comprehensive security validation for agent invocation."""
        execution_id = f"bedrock_exec_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

        claims = self.auth_manager.validate_token(token)
        if not claims:
            return {
                "allowed": False,
                "reason": "authentication_failed",
                "execution_id": execution_id
            }

        # Validate input
        if not self._validate_input_text(input_text):
            self.security_monitor.record_event(
                "malicious_input_detected",
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
            "action_type": "agent_invocation",
            "agent_id": invocation_config.get("agent_id"),
            "alias_id": invocation_config.get("alias_id"),
            "input_length": len(input_text),
            "session_id": session_id,
            "execution_id": execution_id,
            "claims": claims,
            "framework": "bedrock_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_invocation_attempt",
            {
                "execution_id": execution_id,
                "agent_id": invocation_config.get("agent_id"),
                "invoker": claims.get("identity"),
                "session_id": session_id,
                "allowed": is_allowed,
                "input_preview": input_text[:100]
            },
            "INFO" if is_allowed else "WARNING"
        )

        return {
            "allowed": is_allowed,
            "execution_id": execution_id,
            "session_id": session_id,
            "reason": "policy_allowed" if is_allowed else "policy_denied"
        }

    def get_security_context(self, execution_id: str) -> Dict:
        """Get security context for a specific execution."""
        return {
            "execution_id": execution_id,
            "active_agents": len(self.active_agents),
            "kb_access_count": len(self.knowledge_base_access_log),
            "adapter_version": "1.0.0",
            "framework": "bedrock_agent"
        }

    def _validate_kb_query(self, query: str) -> bool:
        """Validate knowledge base query."""
        if not query or len(query) > 5000:
            return False
        suspicious_patterns = ["<script", "javascript:", "drop table", "delete from"]
        for pattern in suspicious_patterns:
            if pattern in query.lower():
                return False
        return True

    def _validate_action_parameters(self, parameters: Dict) -> bool:
        """Validate action group parameters."""
        params_str = str(parameters).lower()
        dangerous_patterns = ["rm -rf", "format c:", "drop table", "<script>"]
        for pattern in dangerous_patterns:
            if pattern in params_str:
                return False
        return True

    def _validate_prompt(self, prompt: str) -> bool:
        """Validate model prompt."""
        if not prompt or len(prompt) > 10000:
            return False
        malicious_patterns = [
            "ignore previous instructions",
            "system: you are now",
            "you are a helpful assistant",
            "<script", "javascript:"
        ]
        for pattern in malicious_patterns:
            if pattern in prompt.lower():
                return False
        return True

    def _validate_guardrail_config(self, config: Dict) -> bool:
        """Validate guardrail configuration."""
        # Ensure guardrails are not disabled
        if config.get("enabled") is False:
            return False
        return True

    def _validate_agent_config(self, config: Dict) -> bool:
        """Validate agent configuration."""
        required_fields = ["agentName", "foundationModel"]
        for field in required_fields:
            if field not in config:
                return False
        return True

    def _validate_input_text(self, text: str) -> bool:
        """Validate input text."""
        if not text or len(text) > 10000:
            return False
        malicious_patterns = [
            "ignore previous instructions",
            "system prompt",
            "<script", "javascript:"
        ]
        for pattern in malicious_patterns:
            if pattern in text.lower():
                return False
        return True
