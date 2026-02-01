"""
Anthropic Claude Agent SDK Integration Adapter for Zero Trust Security Agent

This adapter provides comprehensive zero trust security integration for Anthropic's Claude Agent SDK,
intercepting and validating:
- Message creation and tool use requests
- Tool execution and function calls
- Computer use tool operations
- Extended thinking/reasoning processes
- Agent session management
- Artifact generation and management
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from typing import Any, Dict, Optional, List, Callable, Union
import functools
import json
import inspect
from datetime import datetime, timezone

from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ClaudeAgentAdapter:
    """Zero Trust Security Adapter for Anthropic Claude Agent SDK"""

    def __init__(self, auth_manager: AuthenticationManager, policy_engine: PolicyEngine, security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor
        self.active_sessions = {}  # Track active agent sessions

    def validate_message_creation(self, message_config: Dict, token: str) -> bool:
        """Validate message creation with zero trust principles."""
        # Validate authentication token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_message_creation",
                {"message_config": self._sanitize_config(message_config)},
                "WARNING"
            )
            return False

        # Create security context for policy evaluation
        context = {
            "action_type": "create_message",
            "message_role": message_config.get("role"),
            "message_length": len(message_config.get("content", "")),
            "has_tool_calls": bool(message_config.get("tool_calls")),
            "has_tool_results": bool(message_config.get("tool_results")),
            "claims": claims,
            "framework": "claude_agent"
        }

        # Evaluate against security policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record the creation attempt
        self.security_monitor.record_event(
            "message_creation_attempt",
            {
                "message_role": message_config.get("role"),
                "creator": claims.get("identity"),
                "allowed": is_allowed,
                "has_tool_calls": context["has_tool_calls"],
                "has_tool_results": context["has_tool_results"]
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_tool_use(self, tool_name: str, tool_input: Dict, agent_id: str, token: str) -> bool:
        """Validate tool use execution with comprehensive security checks."""
        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_use",
                {
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "reason": "invalid_token"
                },
                "WARNING"
            )
            return False

        # Validate tool input for potential security risks
        if not self._validate_tool_input(tool_input):
            self.security_monitor.record_event(
                "suspicious_tool_input",
                {
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "input_preview": str(tool_input)[:100]
                },
                "WARNING"
            )
            return False

        # Special handling for computer use tools
        if tool_name in ["computer", "bash", "str_replace_editor"]:
            if not self._validate_computer_use_tool(tool_name, tool_input, claims):
                return False

        # Create context for policy evaluation
        context = {
            "action_type": "use_tool",
            "tool_name": tool_name,
            "agent_id": agent_id,
            "input_size": len(str(tool_input)),
            "is_computer_use": tool_name in ["computer", "bash", "str_replace_editor"],
            "claims": claims,
            "framework": "claude_agent"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record tool use attempt
        self.security_monitor.record_event(
            "tool_use_attempt",
            {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed,
                "is_computer_use": context["is_computer_use"],
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_computer_use_operation(self, operation: str, params: Dict, agent_id: str, token: str) -> bool:
        """Validate computer use tool operations with enhanced security."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_computer_use",
                {"operation": operation, "agent_id": agent_id},
                "WARNING"
            )
            return False

        # Restrict dangerous operations
        dangerous_operations = ["rm", "del", "format", "dd", "mkfs"]
        if operation in dangerous_operations:
            self.security_monitor.record_event(
                "dangerous_computer_use_blocked",
                {
                    "operation": operation,
                    "agent_id": agent_id,
                    "executor": claims.get("identity")
                },
                "CRITICAL"
            )
            return False

        context = {
            "action_type": "computer_use",
            "operation": operation,
            "agent_id": agent_id,
            "params_preview": str(params)[:100],
            "claims": claims,
            "framework": "claude_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "computer_use_attempt",
            {
                "operation": operation,
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_extended_thinking(self, thinking_config: Dict, agent_id: str, token: str) -> bool:
        """Validate extended thinking/reasoning process requests."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        context = {
            "action_type": "extended_thinking",
            "thinking_budget": thinking_config.get("budget_tokens", 0),
            "agent_id": agent_id,
            "claims": claims,
            "framework": "claude_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "extended_thinking_attempt",
            {
                "agent_id": agent_id,
                "thinking_budget": thinking_config.get("budget_tokens"),
                "executor": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_artifact_creation(self, artifact_type: str, artifact_content: Dict, agent_id: str, token: str) -> bool:
        """Validate artifact generation and management."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_artifact_creation",
                {"artifact_type": artifact_type, "agent_id": agent_id},
                "WARNING"
            )
            return False

        # Validate artifact content for security risks
        if not self._validate_artifact_content(artifact_type, artifact_content):
            self.security_monitor.record_event(
                "suspicious_artifact_content",
                {
                    "artifact_type": artifact_type,
                    "agent_id": agent_id
                },
                "WARNING"
            )
            return False

        context = {
            "action_type": "create_artifact",
            "artifact_type": artifact_type,
            "agent_id": agent_id,
            "content_size": len(str(artifact_content)),
            "claims": claims,
            "framework": "claude_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "artifact_creation_attempt",
            {
                "artifact_type": artifact_type,
                "agent_id": agent_id,
                "creator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def validate_agent_session(self, session_id: str, operation: str, session_data: Dict, token: str) -> bool:
        """Validate agent session management operations."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_session_operation",
                {"session_id": session_id, "operation": operation},
                "WARNING"
            )
            return False

        context = {
            "action_type": "session_operation",
            "session_id": session_id,
            "operation": operation,
            "session_data_size": len(str(session_data)),
            "claims": claims,
            "framework": "claude_agent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        # Track session state
        if is_allowed and operation == "create":
            self.active_sessions[session_id] = {
                "created_by": claims.get("identity"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_activity": datetime.now(timezone.utc).isoformat()
            }
        elif operation == "destroy" and session_id in self.active_sessions:
            del self.active_sessions[session_id]

        self.security_monitor.record_event(
            "session_operation_attempt",
            {
                "session_id": session_id,
                "operation": operation,
                "operator": claims.get("identity"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def secure_conversation_turn(self, conversation_config: Dict, user_input: str, session_id: Optional[str] = None, token: str = "") -> Dict:
        """Comprehensive security validation for conversation turns."""
        execution_id = f"claude_exec_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return {
                "allowed": False,
                "reason": "authentication_failed",
                "execution_id": execution_id
            }

        # Validate input for security risks
        if not self._validate_user_input(user_input):
            self.security_monitor.record_event(
                "malicious_input_detected",
                {
                    "execution_id": execution_id,
                    "input_preview": user_input[:100]
                },
                "CRITICAL"
            )
            return {
                "allowed": False,
                "reason": "malicious_input_detected",
                "execution_id": execution_id
            }

        # Create comprehensive security context
        context = {
            "action_type": "conversation_turn",
            "model": conversation_config.get("model", "claude-3-5-sonnet-20241022"),
            "max_tokens": conversation_config.get("max_tokens", 4096),
            "input_length": len(user_input),
            "has_tools": bool(conversation_config.get("tools")),
            "has_computer_use": any(t.get("type") == "computer" for t in conversation_config.get("tools", [])),
            "session_id": session_id,
            "execution_id": execution_id,
            "claims": claims,
            "framework": "claude_agent"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record execution attempt
        self.security_monitor.record_event(
            "conversation_turn_attempt",
            {
                "execution_id": execution_id,
                "model": context["model"],
                "executor": claims.get("identity"),
                "session_id": session_id,
                "allowed": is_allowed,
                "input_preview": user_input[:100]
            },
            "INFO" if is_allowed else "WARNING"
        )

        return {
            "allowed": is_allowed,
            "execution_id": execution_id,
            "session_id": session_id,
            "reason": "policy_allowed" if is_allowed else "policy_denied"
        }

    def create_secure_tool_wrapper(self, func: Callable, token: str) -> Callable:
        """Create a security-wrapped version of a tool function."""
        @functools.wraps(func)
        def secure_wrapper(*args, **kwargs):
            # Extract function metadata
            func_name = func.__name__

            # Validate tool execution
            if not self.validate_tool_use(
                tool_name=func_name,
                tool_input={"args": args, "kwargs": kwargs},
                agent_id=kwargs.get("agent_id", "unknown"),
                token=token
            ):
                raise PermissionError(f"Tool execution denied: {func_name}")

            try:
                # Execute the original function
                result = func(*args, **kwargs)

                # Log successful execution
                self.security_monitor.record_event(
                    "tool_execution_success",
                    {
                        "tool_name": func_name,
                        "agent_id": kwargs.get("agent_id", "unknown"),
                        "result_type": type(result).__name__
                    },
                    "INFO"
                )
                return result
            except Exception as e:
                # Log execution failure
                self.security_monitor.record_event(
                    "tool_execution_failure",
                    {
                        "tool_name": func_name,
                        "agent_id": kwargs.get("agent_id", "unknown"),
                        "error": str(e),
                        "error_type": type(e).__name__
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
            "session_list": list(self.active_sessions.keys()),
            "adapter_version": "1.0.0",
            "framework": "claude_agent"
        }

    def _sanitize_config(self, config: Dict) -> Dict:
        """Sanitize configuration for logging (remove sensitive data)."""
        sanitized = config.copy()
        sensitive_fields = ["api_key", "secret", "password", "token", "anthropic_api_key"]
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = "***MASKED***"
        return sanitized

    def _validate_tool_input(self, tool_input: Dict) -> bool:
        """Validate tool input for security risks."""
        input_str = str(tool_input).lower()

        # Check for common injection patterns
        suspicious_patterns = [
            "rm -rf", "del /", "format c:",
            "drop table", "delete from", "update", "insert into",
            "<script>", "javascript:", "eval(",
            "__import__", "exec(", "eval(",
            "../", "..\\",
        ]

        for pattern in suspicious_patterns:
            if pattern in input_str:
                return False
        return True

    def _validate_computer_use_tool(self, tool_name: str, tool_input: Dict, claims: Dict) -> bool:
        """Additional validation for computer use tools."""
        # Require elevated permissions for computer use
        if tool_name == "bash":
            command = tool_input.get("command", "").lower()
            dangerous_commands = ["rm", "del", "format", "dd", "mkfs", "fdisk"]
            for dangerous in dangerous_commands:
                if dangerous in command:
                    self.security_monitor.record_event(
                        "dangerous_bash_command_blocked",
                        {
                            "command": command[:100],
                            "executor": claims.get("identity")
                        },
                        "CRITICAL"
                    )
                    return False
        return True

    def _validate_artifact_content(self, artifact_type: str, content: Dict) -> bool:
        """Validate artifact content for security risks."""
        content_str = str(content).lower()

        # Check for malicious patterns in artifacts
        malicious_patterns = [
            "<script", "javascript:", "onerror=", "onload=",
            "data:text/html", "vbscript:", "mocha:", "livescript:"
        ]

        for pattern in malicious_patterns:
            if pattern in content_str:
                return False
        return True

    def _validate_user_input(self, user_input: str) -> bool:
        """Validate user input for security risks."""
        if not user_input or len(user_input) > 10000:
            return False

        input_lower = user_input.lower()

        # Check for malicious patterns
        malicious_patterns = [
            "ignore previous instructions",
            "system: you are now",
            "you are a helpful assistant",
            "ignore all prior",
            "disregard previous",
            "new instructions:",
            "<script", "javascript:", "data:text/html"
        ]

        for pattern in malicious_patterns:
            if pattern in input_lower:
                return False
        return True
