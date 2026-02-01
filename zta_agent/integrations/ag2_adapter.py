""" AG2 (AutoGen v2) Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class AG2Adapter:
    """Adapter for integrating Zero Trust Security with AG2 (AutoGen v2).
    
    AG2 is the next-generation version of AutoGen with improved architecture.
    This adapter provides security validation for:
    - Agent registration and management
    - Message routing between agents
    - Code execution in agents
    - Group chat operations
    - Tool usage in agents
    """

    def __init__(
        self,
        auth_manager: AuthenticationManager,
        policy_engine: PolicyEngine,
        security_monitor: SecurityMonitor
    ):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor

    def validate_agent_registration(
        self,
        agent_id: str,
        agent_config: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate if an agent can be registered in AG2.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_config: Agent configuration (type, capabilities, etc.)
            token: Authentication token
            
        Returns:
            bool: True if registration is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_registration",
                {"agent_id": agent_id, "agent_type": agent_config.get("type")},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "agent_type": agent_config.get("type"),
            "agent_capabilities": agent_config.get("capabilities", []),
            "can_execute_code": agent_config.get("can_execute_code", False),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_registration_validation",
            {
                "agent_id": agent_id,
                "agent_type": agent_config.get("type"),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_message_routing(
        self,
        sender_id: str,
        recipient_id: str,
        message: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate message routing between AG2 agents.
        
        Args:
            sender_id: ID of the sending agent
            recipient_id: ID of the receiving agent
            message: Message content and metadata
            token: Authentication token
            
        Returns:
            bool: True if routing is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_message_routing",
                {"sender_id": sender_id, "recipient_id": recipient_id},
                "WARNING"
            )
            return False

        context = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "message_type": message.get("type"),
            "has_code": "code" in message.get("content", "").lower(),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "message_routing_validation",
            {
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "message_type": message.get("type"),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_code_execution(
        self,
        agent_id: str,
        code: str,
        language: str,
        token: str
    ) -> bool:
        """Validate code execution in AG2 agents.
        
        Args:
            agent_id: ID of the agent requesting execution
            code: Code to be executed
            language: Programming language (python, bash, etc.)
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_code_execution",
                {"agent_id": agent_id, "language": language},
                "WARNING"
            )
            return False

        # Check for dangerous patterns
        dangerous_patterns = [
            "rm -rf", "os.system", "subprocess", "eval(", "exec(",
            "__import__", "import os", "import subprocess"
        ]
        has_dangerous = any(pattern in code.lower() for pattern in dangerous_patterns)

        context = {
            "agent_id": agent_id,
            "language": language,
            "code_length": len(code),
            "has_dangerous_patterns": has_dangerous,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "code_execution_validation",
            {
                "agent_id": agent_id,
                "language": language,
                "has_dangerous_patterns": has_dangerous,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_group_chat_operation(
        self,
        operation: str,
        group_id: str,
        agent_ids: List[str],
        token: str
    ) -> bool:
        """Validate group chat operations in AG2.
        
        Args:
            operation: Operation type (create, join, leave, send)
            group_id: Group chat identifier
            agent_ids: List of agents involved
            token: Authentication token
            
        Returns:
            bool: True if operation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_group_chat_operation",
                {"operation": operation, "group_id": group_id},
                "WARNING"
            )
            return False

        context = {
            "operation": operation,
            "group_id": group_id,
            "agent_count": len(agent_ids),
            "agent_ids": agent_ids,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "group_chat_operation_validation",
            {
                "operation": operation,
                "group_id": group_id,
                "agent_count": len(agent_ids),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_tool_usage(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate tool usage by AG2 agents.
        
        Args:
            agent_id: ID of the agent using the tool
            tool_name: Name of the tool
            tool_args: Tool arguments
            token: Authentication token
            
        Returns:
            bool: True if tool usage is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_usage",
                {"agent_id": agent_id, "tool_name": tool_name},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "tool_args_keys": list(tool_args.keys()),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_usage_validation",
            {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_agent(
        self,
        agent_func: Callable,
        agent_id: str,
        agent_config: Dict[str, Any],
        token: str
    ) -> Callable:
        """Wrap an AG2 agent with security validation.
        
        Args:
            agent_func: Original agent function/class
            agent_id: Agent identifier
            agent_config: Agent configuration
            token: Authentication token
            
        Returns:
            Callable: Secured agent
        """
        def secured_agent(*args, **kwargs) -> Any:
            # Validate agent registration
            if not self.validate_agent_registration(agent_id, agent_config, token):
                self.security_monitor.record_event(
                    "agent_blocked",
                    {"agent_id": agent_id},
                    "ERROR"
                )
                raise PermissionError(f"Agent registration blocked: {agent_id}")

            # Execute the original agent
            try:
                result = agent_func(*args, **kwargs)
                self.security_monitor.record_event(
                    "agent_execution_success",
                    {"agent_id": agent_id},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "agent_execution_error",
                    {"agent_id": agent_id, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_agent

    def validate_llm_call(
        self,
        agent_id: str,
        model: str,
        messages: List[Dict[str, str]],
        token: str
    ) -> bool:
        """Validate LLM API calls from AG2 agents.
        
        Args:
            agent_id: ID of the agent making the call
            model: Model name/identifier
            messages: List of messages for the LLM
            token: Authentication token
            
        Returns:
            bool: True if LLM call is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_llm_call",
                {"agent_id": agent_id, "model": model},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "model": model,
            "message_count": len(messages),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "ag2"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "llm_call_validation",
            {
                "agent_id": agent_id,
                "model": model,
                "message_count": len(messages),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
