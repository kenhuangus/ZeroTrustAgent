"""
OpenAI Agents SDK Integration Adapter for Zero Trust Security Agent

This adapter provides comprehensive zero trust security integration for OpenAI Agents SDK,
intercepting and validating:
- Agent creation and configuration
- Tool execution and function calls
- Agent handoffs and communication
- Session management and state changes
- Input/output validation (Guardrails integration)
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from typing import Any, Dict, Optional, List, Callable, Union
import functools
import json
import inspect
from datetime import datetime

from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor
from ..utils.logger import get_logger

logger = get_logger(__name__)


class OpenAIAgentAdapter:
    """Zero Trust Security Adapter for OpenAI Agents SDK"""
    
    def __init__(self, 
                 auth_manager: AuthenticationManager, 
                 policy_engine: PolicyEngine,
                 security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor
        self.active_sessions = {}  # Track active agent sessions
        
    def validate_agent_creation(self, agent_config: Dict, token: str) -> bool:
        """Validate agent creation with zero trust principles."""
        # Validate authentication token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_creation",
                {"agent_config": self._sanitize_config(agent_config)},
                "WARNING"
            )
            return False
        
        # Create security context for policy evaluation
        context = {
            "action_type": "create_agent",
            "agent_name": agent_config.get("name"),
            "agent_instructions": agent_config.get("instructions", "")[:200],  # Truncate for logging
            "tools_count": len(agent_config.get("tools", [])),
            "handoffs_count": len(agent_config.get("handoffs", [])),
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate against security policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record the creation attempt
        self.security_monitor.record_event(
            "agent_creation_attempt",
            {
                "agent_name": agent_config.get("name"),
                "creator": claims.get("identity"),
                "allowed": is_allowed,
                "tools_count": context["tools_count"],
                "handoffs_count": context["handoffs_count"]
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed
    
    def validate_tool_execution(self, 
                              tool_name: str, 
                              tool_args: Dict, 
                              agent_id: str, 
                              token: str) -> bool:
        """Validate tool/function execution with comprehensive security checks."""
        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_execution",
                {
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "reason": "invalid_token"
                },
                "WARNING"
            )
            return False
        
        # Validate tool arguments for potential security risks
        if not self._validate_tool_arguments(tool_args):
            self.security_monitor.record_event(
                "suspicious_tool_arguments",
                {
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "args_preview": str(tool_args)[:100]
                },
                "WARNING"
            )
            return False
        
        # Create context for policy evaluation
        context = {
            "action_type": "execute_tool",
            "tool_name": tool_name,
            "agent_id": agent_id,
            "args_count": len(tool_args),
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record tool execution attempt
        self.security_monitor.record_event(
            "tool_execution_attempt",
            {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed,
                "timestamp": datetime.utcnow().isoformat()
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed
    
    def validate_agent_handoff(self, 
                             source_agent: str, 
                             target_agent: str, 
                             handoff_context: Dict, 
                             token: str) -> bool:
        """Validate agent-to-agent handoffs with zero trust verification."""
        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_handoff_attempt",
                {
                    "source_agent": source_agent,
                    "target_agent": target_agent,
                    "reason": "invalid_token"
                },
                "WARNING"
            )
            return False
        
        # Create security context
        context = {
            "action_type": "agent_handoff",
            "source_agent": source_agent,
            "target_agent": target_agent,
            "handoff_reason": handoff_context.get("reason", ""),
            "context_size": len(str(handoff_context)),
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record handoff attempt
        self.security_monitor.record_event(
            "agent_handoff_attempt",
            {
                "source_agent": source_agent,
                "target_agent": target_agent,
                "initiator": claims.get("identity"),
                "allowed": is_allowed,
                "context_preview": str(handoff_context)[:200]
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed
    
    def validate_session_operation(self, 
                                 session_id: str, 
                                 operation: str, 
                                 session_data: Dict, 
                                 token: str) -> bool:
        """Validate session management operations."""
        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_session_operation",
                {
                    "session_id": session_id,
                    "operation": operation,
                    "reason": "invalid_token"
                },
                "WARNING"
            )
            return False
        
        # Create context for policy evaluation
        context = {
            "action_type": "session_operation",
            "session_id": session_id,
            "operation": operation,
            "session_data_size": len(str(session_data)),
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Track session state
        if is_allowed and operation == "create":
            self.active_sessions[session_id] = {
                "created_by": claims.get("identity"),
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat()
            }
        elif operation == "destroy" and session_id in self.active_sessions:
            del self.active_sessions[session_id]
        
        # Record session operation
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
    
    def validate_guardrail_execution(self, 
                                   guardrail_name: str, 
                                   input_data: Any, 
                                   agent_id: str, 
                                   token: str) -> bool:
        """Validate guardrail execution and input validation."""
        # Validate authentication
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False
        
        # Create context for guardrail validation
        context = {
            "action_type": "execute_guardrail",
            "guardrail_name": guardrail_name,
            "agent_id": agent_id,
            "input_size": len(str(input_data)) if input_data else 0,
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record guardrail execution
        self.security_monitor.record_event(
            "guardrail_execution",
            {
                "guardrail_name": guardrail_name,
                "agent_id": agent_id,
                "executor": claims.get("identity"),
                "allowed": is_allowed,
                "input_preview": str(input_data)[:100] if input_data else ""
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed
    
    def secure_runner_execution(self, 
                              agent_config: Dict, 
                              user_input: str, 
                              session_id: Optional[str] = None,
                              token: str = "") -> Dict:
        """Comprehensive security validation for runner execution."""
        execution_id = f"exec_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}"
        
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
                    "agent": agent_config.get("name"),
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
            "action_type": "runner_execution",
            "agent_name": agent_config.get("name"),
            "input_length": len(user_input),
            "session_id": session_id,
            "execution_id": execution_id,
            "claims": claims,
            "framework": "openai_agents"
        }
        
        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record execution attempt
        self.security_monitor.record_event(
            "runner_execution_attempt",
            {
                "execution_id": execution_id,
                "agent_name": agent_config.get("name"),
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
            "session_id": session_id
        }
    
    def create_secure_function_tool(self, func: Callable, token: str) -> Callable:
        """Create a security-wrapped version of a function tool."""
        @functools.wraps(func)
        def secure_wrapper(*args, **kwargs):
            # Extract function metadata
            func_name = func.__name__
            func_signature = str(inspect.signature(func))
            
            # Validate tool execution
            if not self.validate_tool_execution(
                tool_name=func_name,
                tool_args={"args": args, "kwargs": kwargs},
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
            "framework": "openai_agents"
        }
    
    def _sanitize_config(self, config: Dict) -> Dict:
        """Sanitize configuration for logging (remove sensitive data)."""
        sanitized = config.copy()
        # Remove or mask sensitive fields
        sensitive_fields = ["api_key", "secret", "password", "token"]
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = "***MASKED***"
        return sanitized
    
    def _validate_tool_arguments(self, args: Dict) -> bool:
        """Validate tool arguments for security risks."""
        args_str = str(args).lower()
        
        # Check for common injection patterns
        suspicious_patterns = [
            "rm -rf", "del /", "format c:",  # File system commands
            "drop table", "delete from", "update", "insert into",  # SQL injection
            "<script>", "javascript:", "eval(",  # Script injection
            "__import__", "exec(", "eval(",  # Code execution
            "../", "..\\",  # Path traversal
        ]
        
        for pattern in suspicious_patterns:
            if pattern in args_str:
                return False
        
        return True
    
    def _validate_user_input(self, user_input: str) -> bool:
        """Validate user input for security risks."""
        if not user_input or len(user_input) > 10000:  # Prevent DoS via large inputs
            return False
        
        input_lower = user_input.lower()
        
        # Check for malicious patterns
        malicious_patterns = [
            "ignore previous instructions",
            "system: you are now",
            "#!/bin/", 
            "powershell -",
            "cmd.exe",
            "<script",
            "javascript:",
            "data:text/html",
            "file://",
            "ftp://"
        ]
        
        for pattern in malicious_patterns:
            if pattern in input_lower:
                return False
        
        return True