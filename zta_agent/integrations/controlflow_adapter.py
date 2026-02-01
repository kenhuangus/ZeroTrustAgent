""" ControlFlow Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class ControlFlowAdapter:
    """Adapter for integrating Zero Trust Security with ControlFlow.
    
    ControlFlow is a framework for building data pipelines with AI agents.
    This adapter provides security validation for:
    - Flow creation and execution
    - Task creation and assignment
    - Agent registration
    - Tool usage
    - Context/data access
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

    def validate_flow_creation(
        self,
        flow_id: str,
        flow_config: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate ControlFlow flow creation.
        
        Args:
            flow_id: Unique identifier for the flow
            flow_config: Flow configuration
            token: Authentication token
            
        Returns:
            bool: True if creation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_flow_creation",
                {"flow_id": flow_id},
                "WARNING"
            )
            return False

        context = {
            "flow_id": flow_id,
            "flow_name": flow_config.get("name"),
            "task_count": len(flow_config.get("tasks", [])),
            "agent_count": len(flow_config.get("agents", [])),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "flow_creation_validation",
            {
                "flow_id": flow_id,
                "flow_name": flow_config.get("name"),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_flow_execution(
        self,
        flow_id: str,
        input_data: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate ControlFlow flow execution.
        
        Args:
            flow_id: Flow identifier
            input_data: Input data for the flow
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_flow_execution",
                {"flow_id": flow_id},
                "WARNING"
            )
            return False

        context = {
            "flow_id": flow_id,
            "input_keys": list(input_data.keys()),
            "input_size": len(str(input_data)),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "flow_execution_validation",
            {
                "flow_id": flow_id,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_task_creation(
        self,
        task_id: str,
        task_config: Dict[str, Any],
        flow_id: str,
        token: str
    ) -> bool:
        """Validate ControlFlow task creation.
        
        Args:
            task_id: Task identifier
            task_config: Task configuration
            flow_id: Parent flow identifier
            token: Authentication token
            
        Returns:
            bool: True if creation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_task_creation",
                {"task_id": task_id, "flow_id": flow_id},
                "WARNING"
            )
            return False

        context = {
            "task_id": task_id,
            "task_name": task_config.get("name"),
            "task_type": task_config.get("type"),
            "flow_id": flow_id,
            "assigned_agent": task_config.get("agent"),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "task_creation_validation",
            {
                "task_id": task_id,
                "task_name": task_config.get("name"),
                "flow_id": flow_id,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_agent_registration(
        self,
        agent_id: str,
        agent_config: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate ControlFlow agent registration.
        
        Args:
            agent_id: Agent identifier
            agent_config: Agent configuration
            token: Authentication token
            
        Returns:
            bool: True if registration is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_registration",
                {"agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "agent_name": agent_config.get("name"),
            "agent_model": agent_config.get("model"),
            "has_tools": bool(agent_config.get("tools", [])),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_registration_validation",
            {
                "agent_id": agent_id,
                "agent_name": agent_config.get("name"),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_tool_usage(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: str,
        task_id: str,
        token: str
    ) -> bool:
        """Validate ControlFlow tool usage.
        
        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments
            agent_id: ID of the using agent
            task_id: ID of the current task
            token: Authentication token
            
        Returns:
            bool: True if usage is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_usage",
                {"tool_name": tool_name, "agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "tool_name": tool_name,
            "tool_args_keys": list(tool_args.keys()),
            "agent_id": agent_id,
            "task_id": task_id,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_usage_validation",
            {
                "tool_name": tool_name,
                "agent_id": agent_id,
                "task_id": task_id,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_context_access(
        self,
        context_key: str,
        access_type: str,
        flow_id: str,
        token: str
    ) -> bool:
        """Validate ControlFlow context/data access.
        
        Args:
            context_key: Context key being accessed
            access_type: Type of access (read, write)
            flow_id: Flow identifier
            token: Authentication token
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_context_access",
                {"context_key": context_key, "flow_id": flow_id},
                "WARNING"
            )
            return False

        context = {
            "context_key": context_key,
            "access_type": access_type,
            "flow_id": flow_id,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "controlflow"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "context_access_validation",
            {
                "context_key": context_key,
                "access_type": access_type,
                "flow_id": flow_id,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_flow(
        self,
        flow_func: Callable,
        flow_id: str,
        flow_config: Dict[str, Any],
        token: str
    ) -> Callable:
        """Wrap a ControlFlow flow with security validation.
        
        Args:
            flow_func: Original flow function
            flow_id: Flow identifier
            flow_config: Flow configuration
            token: Authentication token
            
        Returns:
            Callable: Secured flow function
        """
        def secured_flow(*args, **kwargs) -> Any:
            # Validate flow creation
            if not self.validate_flow_creation(flow_id, flow_config, token):
                self.security_monitor.record_event(
                    "flow_blocked",
                    {"flow_id": flow_id},
                    "ERROR"
                )
                raise PermissionError(f"Flow creation blocked: {flow_id}")

            # Execute the original flow
            try:
                result = flow_func(*args, **kwargs)
                self.security_monitor.record_event(
                    "flow_execution_success",
                    {"flow_id": flow_id},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "flow_execution_error",
                    {"flow_id": flow_id, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_flow
