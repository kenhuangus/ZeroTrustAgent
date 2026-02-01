"""
Google Agent SDK (Vertex AI / Gemini) Integration Adapter for Zero Trust Security Agent

This adapter provides comprehensive zero trust security integration for Google's Agent SDK,
intercepting and validating:
- Function calling and tool use
- Grounding and retrieval operations
- Multi-turn chat sessions
- Agent deployment on Vertex AI
- Content generation and safety settings
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


class GoogleAgentAdapter:
    """Zero Trust Security Adapter for Google Agent SDK (Vertex AI / Gemini)"""

    def __init__(self, auth_manager: AuthenticationManager, policy_engine: PolicyEngine, security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor
        self.active_sessions = {}
        self.grounding_cache = {}

    def validate_function_calling(self, function_name: str, function_args: Dict, agent_id: str, token: str) -> bool:
        """Validate Gemini function calling with security checks."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_function_call",
                {"function_name": function_name, "agent_id": agent_id},
                "WARNING"
            )
            return False

        # Validate function arguments
        if not self._validate_function_args(function_args):
            self.security_monitor.record_event(
                "suspicious_function_args",
                {
                    "function_name": function_name,
                    "agent_id": agent_id,
                    "args_preview": str(function_args)[:100]
                },
                "WARNING"
            )
            return False

        context = {
            "action_type": "function_call",
            "function_name": function_name,
            "agent_id": agent_id,
            "args_count": len(function_args),
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "function_call_attempt",
            {
                "function_name": function_name,
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_grounding(self, query: str, sources: List[str], agent_id: str, token: str) -> bool:
        """Validate grounding and retrieval operations."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_grounding",
                {"query_preview": query[:100], "agent_id": agent_id},
                "WARNING"
            )
            return False

        # Validate query for security
        if not self._validate_grounding_query(query):
            self.security_monitor.record_event(
                "suspicious_grounding_query",
                {"query": query[:100], "agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "grounding",
            "query_length": len(query),
            "sources_count": len(sources),
            "agent_id": agent_id,
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        # Cache grounding request for audit
        grounding_id = f"ground_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"
        self.grounding_cache[grounding_id] = {
            "query": query[:200],
            "sources": sources,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "allowed": is_allowed
        }

        self.security_monitor.record_event(
            "grounding_attempt",
            {
                "grounding_id": grounding_id,
                "query_preview": query[:100],
                "sources_count": len(sources),
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_multi_turn_chat(self, chat_history: List[Dict], new_message: str, agent_id: str, token: str) -> bool:
        """Validate multi-turn chat sessions."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_chat",
                {"agent_id": agent_id},
                "WARNING"
            )
            return False

        # Validate new message
        if not self._validate_chat_message(new_message):
            self.security_monitor.record_event(
                "malicious_chat_message",
                {"message_preview": new_message[:100], "agent_id": agent_id},
                "CRITICAL"
            )
            return False

        # Check chat history length for DoS prevention
        if len(chat_history) > 100:
            self.security_monitor.record_event(
                "chat_history_limit_exceeded",
                {"history_length": len(chat_history), "agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "multi_turn_chat",
            "history_length": len(chat_history),
            "message_length": len(new_message),
            "agent_id": agent_id,
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "chat_attempt",
            {
                "history_length": len(chat_history),
                "message_preview": new_message[:100],
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_agent_deployment(self, deployment_config: Dict, project_id: str, token: str) -> bool:
        """Validate Vertex AI Agent deployment."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_deployment",
                {"project_id": project_id},
                "WARNING"
            )
            return False

        # Validate deployment configuration
        if not self._validate_deployment_config(deployment_config):
            self.security_monitor.record_event(
                "invalid_deployment_config",
                {"project_id": project_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "agent_deployment",
            "project_id": project_id,
            "agent_name": deployment_config.get("display_name"),
            "model": deployment_config.get("model"),
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "deployment_attempt",
            {
                "project_id": project_id,
                "agent_name": deployment_config.get("display_name"),
                "model": deployment_config.get("model"),
                "deployer": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_content_generation(self, content_config: Dict, prompt: str, agent_id: str, token: str) -> bool:
        """Validate content generation requests with safety settings."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_content_generation",
                {"agent_id": agent_id},
                "WARNING"
            )
            return False

        # Validate prompt
        if not self._validate_generation_prompt(prompt):
            self.security_monitor.record_event(
                "malicious_generation_prompt",
                {"prompt_preview": prompt[:100], "agent_id": agent_id},
                "CRITICAL"
            )
            return False

        # Check safety settings
        safety_settings = content_config.get("safety_settings", {})
        if not self._validate_safety_settings(safety_settings):
            self.security_monitor.record_event(
                "unsafe_safety_settings",
                {"agent_id": agent_id, "settings": safety_settings},
                "WARNING"
            )
            return False

        context = {
            "action_type": "content_generation",
            "prompt_length": len(prompt),
            "temperature": content_config.get("temperature", 0.7),
            "max_output_tokens": content_config.get("max_output_tokens", 2048),
            "agent_id": agent_id,
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "content_generation_attempt",
            {
                "prompt_preview": prompt[:100],
                "temperature": content_config.get("temperature"),
                "max_tokens": content_config.get("max_output_tokens"),
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_tool_declaration(self, tool_name: str, tool_schema: Dict, agent_id: str, token: str) -> bool:
        """Validate tool/function declaration."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        # Validate tool schema
        if not self._validate_tool_schema(tool_schema):
            self.security_monitor.record_event(
                "invalid_tool_schema",
                {"tool_name": tool_name, "agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "action_type": "tool_declaration",
            "tool_name": tool_name,
            "schema_complexity": len(str(tool_schema)),
            "agent_id": agent_id,
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_declaration_attempt",
            {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "declarer": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def secure_chat_session(self, session_config: Dict, initial_message: str, session_id: Optional[str] = None, token: str = "") -> Dict:
        """Comprehensive security validation for chat sessions."""
        execution_id = f"google_exec_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

        claims = self.auth_manager.validate_token(token)
        if not claims:
            return {
                "allowed": False,
                "reason": "authentication_failed",
                "execution_id": execution_id
            }

        if not self._validate_chat_message(initial_message):
            self.security_monitor.record_event(
                "malicious_chat_input",
                {
                    "execution_id": execution_id,
                    "input_preview": initial_message[:100]
                },
                "CRITICAL"
            )
            return {
                "allowed": False,
                "reason": "malicious_input_detected",
                "execution_id": execution_id
            }

        context = {
            "action_type": "chat_session",
            "model": session_config.get("model", "gemini-pro"),
            "temperature": session_config.get("temperature", 0.7),
            "input_length": len(initial_message),
            "has_tools": bool(session_config.get("tools")),
            "has_grounding": bool(session_config.get("enable_grounding")),
            "session_id": session_id,
            "execution_id": execution_id,
            "claims": claims,
            "framework": "google_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        if is_allowed and session_id:
            self.active_sessions[session_id] = {
                "created_by": claims.get("identity"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "model": context["model"]
            }

        self.security_monitor.record_event(
            "chat_session_attempt",
            {
                "execution_id": execution_id,
                "model": context["model"],
                "executor": claims.get("identity"),
                "session_id": session_id,
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return {
            "allowed": is_allowed,
            "execution_id": execution_id,
            "session_id": session_id,
            "reason": "policy_allowed" if is_allowed else "policy_denied"
        }

    def create_secure_tool(self, func: Callable, token: str) -> Callable:
        """Create a security-wrapped version of a tool function."""
        @functools.wraps(func)
        def secure_wrapper(*args, **kwargs):
            func_name = func.__name__

            if not self.validate_function_calling(
                function_name=func_name,
                function_args={"args": args, "kwargs": kwargs},
                agent_id=kwargs.get("agent_id", "unknown"),
                token=token
            ):
                raise PermissionError(f"Function calling denied: {func_name}")

            try:
                result = func(*args, **kwargs)
                self.security_monitor.record_event(
                    "function_execution_success",
                    {
                        "function_name": func_name,
                        "agent_id": kwargs.get("agent_id", "unknown")
                    },
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "function_execution_failure",
                    {
                        "function_name": func_name,
                        "agent_id": kwargs.get("agent_id", "unknown"),
                        "error": str(e)
                    },
                    "ERROR"
                )
                raise

        return secure_wrapper

    def get_security_context(self, execution_id: str) -> Dict:
        """Get security context for a specific execution."""
        return {
            "execution_id": execution_id,
            "active_sessions": len(self.active_sessions),
            "grounding_cache_size": len(self.grounding_cache),
            "adapter_version": "1.0.0",
            "framework": "google_agent"
        }

    def _validate_function_args(self, args: Dict) -> bool:
        """Validate function arguments for security risks."""
        args_str = str(args).lower()
        suspicious_patterns = [
            "rm -rf", "del /", "format c:",
            "drop table", "delete from",
            "<script>", "javascript:",
            "__import__", "exec(", "eval("
        ]
        for pattern in suspicious_patterns:
            if pattern in args_str:
                return False
        return True

    def _validate_grounding_query(self, query: str) -> bool:
        """Validate grounding query."""
        if not query or len(query) > 5000:
            return False
        return True

    def _validate_chat_message(self, message: str) -> bool:
        """Validate chat message for security."""
        if not message or len(message) > 10000:
            return False
        malicious_patterns = [
            "ignore previous instructions",
            "system: you are now",
            "<script", "javascript:"
        ]
        for pattern in malicious_patterns:
            if pattern in message.lower():
                return False
        return True

    def _validate_deployment_config(self, config: Dict) -> bool:
        """Validate deployment configuration."""
        required_fields = ["display_name", "model"]
        for field in required_fields:
            if field not in config:
                return False
        return True

    def _validate_generation_prompt(self, prompt: str) -> bool:
        """Validate generation prompt."""
        if not prompt or len(prompt) > 15000:
            return False
        malicious_patterns = [
            "ignore previous instructions",
            "system prompt",
            "reveal your instructions"
        ]
        for pattern in malicious_patterns:
            if pattern in prompt.lower():
                return False
        return True

    def _validate_safety_settings(self, settings: Dict) -> bool:
        """Validate safety settings are appropriate."""
        # Ensure safety settings are not disabled
        for category, threshold in settings.items():
            if threshold == "BLOCK_NONE":
                return False
        return True

    def _validate_tool_schema(self, schema: Dict) -> bool:
        """Validate tool schema."""
        if not schema or "type" not in schema:
            return False
        return True
