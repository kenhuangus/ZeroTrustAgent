""" Pydantic AI Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable, Type
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class PydanticAIAdapter:
    """Adapter for integrating Zero Trust Security with Pydantic AI.
    
    Pydantic AI is a type-safe agent framework built on Pydantic.
    This adapter provides security validation for:
    - Agent creation and registration
    - Tool/Dependency injection
    - Result validation
    - Model calls
    - Context access
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

    def validate_agent_creation(
        self,
        agent_name: str,
        model: str,
        result_type: Optional[Type],
        deps_type: Optional[Type],
        token: str
    ) -> bool:
        """Validate Pydantic AI agent creation.
        
        Args:
            agent_name: Name of the agent
            model: Model name/identifier
            result_type: Expected result type
            deps_type: Dependencies type
            token: Authentication token
            
        Returns:
            bool: True if creation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_creation",
                {"agent_name": agent_name, "model": model},
                "WARNING"
            )
            return False

        context = {
            "agent_name": agent_name,
            "model": model,
            "result_type": result_type.__name__ if result_type else None,
            "deps_type": deps_type.__name__ if deps_type else None,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_creation_validation",
            {
                "agent_name": agent_name,
                "model": model,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_tool_registration(
        self,
        tool_name: str,
        tool_signature: str,
        agent_name: str,
        token: str
    ) -> bool:
        """Validate tool registration with Pydantic AI agents.
        
        Args:
            tool_name: Name of the tool
            tool_signature: Tool function signature
            agent_name: Name of the agent registering the tool
            token: Authentication token
            
        Returns:
            bool: True if registration is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_registration",
                {"tool_name": tool_name, "agent_name": agent_name},
                "WARNING"
            )
            return False

        context = {
            "tool_name": tool_name,
            "tool_signature": tool_signature,
            "agent_name": agent_name,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_registration_validation",
            {
                "tool_name": tool_name,
                "agent_name": agent_name,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_dependency_injection(
        self,
        agent_name: str,
        dep_name: str,
        dep_type: str,
        token: str
    ) -> bool:
        """Validate dependency injection for Pydantic AI agents.
        
        Args:
            agent_name: Name of the agent
            dep_name: Dependency name
            dep_type: Dependency type
            token: Authentication token
            
        Returns:
            bool: True if injection is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_dependency_injection",
                {"agent_name": agent_name, "dep_name": dep_name},
                "WARNING"
            )
            return False

        context = {
            "agent_name": agent_name,
            "dep_name": dep_name,
            "dep_type": dep_type,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "dependency_injection_validation",
            {
                "agent_name": agent_name,
                "dep_name": dep_name,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_model_call(
        self,
        agent_name: str,
        model: str,
        prompt: str,
        token: str
    ) -> bool:
        """Validate model API calls from Pydantic AI agents.
        
        Args:
            agent_name: Name of the agent
            model: Model name/identifier
            prompt: Prompt being sent
            token: Authentication token
            
        Returns:
            bool: True if call is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_model_call",
                {"agent_name": agent_name, "model": model},
                "WARNING"
            )
            return False

        context = {
            "agent_name": agent_name,
            "model": model,
            "prompt": prompt,
            "prompt_length": len(prompt),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "model_call_validation",
            {
                "agent_name": agent_name,
                "model": model,
                "prompt_preview": prompt[:100],
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_result_type(
        self,
        agent_name: str,
        result_type: Type,
        validation_result: bool,
        token: str
    ) -> bool:
        """Validate result type checking in Pydantic AI.
        
        Args:
            agent_name: Name of the agent
            result_type: Expected result type
            validation_result: Whether validation passed
            token: Authentication token
            
        Returns:
            bool: True if result type is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_result_validation",
                {"agent_name": agent_name, "result_type": result_type.__name__},
                "WARNING"
            )
            return False

        context = {
            "agent_name": agent_name,
            "result_type": result_type.__name__,
            "validation_passed": validation_result,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "result_type_validation",
            {
                "agent_name": agent_name,
                "result_type": result_type.__name__,
                "validation_passed": validation_result,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_agent(
        self,
        agent_func: Callable,
        agent_name: str,
        model: str,
        token: str
    ) -> Callable:
        """Wrap a Pydantic AI agent with security validation.
        
        Args:
            agent_func: Original agent function/class
            agent_name: Name of the agent
            model: Model name
            token: Authentication token
            
        Returns:
            Callable: Secured agent
        """
        def secured_agent(*args, **kwargs) -> Any:
            # Validate agent creation
            if not self.validate_agent_creation(
                agent_name, model, None, None, token
            ):
                self.security_monitor.record_event(
                    "agent_blocked",
                    {"agent_name": agent_name},
                    "ERROR"
                )
                raise PermissionError(f"Agent creation blocked: {agent_name}")

            # Execute the original agent
            try:
                result = agent_func(*args, **kwargs)
                self.security_monitor.record_event(
                    "agent_execution_success",
                    {"agent_name": agent_name},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "agent_execution_error",
                    {"agent_name": agent_name, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_agent

    def validate_context_access(
        self,
        agent_name: str,
        context_key: str,
        access_type: str,
        token: str
    ) -> bool:
        """Validate context access for Pydantic AI agents.
        
        Args:
            agent_name: Name of the agent
            context_key: Context key being accessed
            access_type: Type of access (read, write)
            token: Authentication token
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_context_access",
                {"agent_name": agent_name, "context_key": context_key},
                "WARNING"
            )
            return False

        context = {
            "agent_name": agent_name,
            "context_key": context_key,
            "access_type": access_type,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "pydantic_ai"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "context_access_validation",
            {
                "agent_name": agent_name,
                "context_key": context_key,
                "access_type": access_type,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
