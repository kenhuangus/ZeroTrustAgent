""" Superagent Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class SuperagentAdapter:
    """Adapter for integrating Zero Trust Security with Superagent.
    
    Superagent is a simple, open-source framework for building AI agents.
    This adapter provides security validation for:
    - Agent creation and management
    - Workflow execution
    - Tool invocation
    - LLM calls
    - Document processing
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
        agent_id: str,
        agent_config: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate Superagent agent creation.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_config: Agent configuration
            token: Authentication token
            
        Returns:
            bool: True if creation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_creation",
                {"agent_id": agent_id, "agent_type": agent_config.get("type")},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "agent_type": agent_config.get("type"),
            "agent_llm": agent_config.get("llm"),
            "has_tools": bool(agent_config.get("tools", [])),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_creation_validation",
            {
                "agent_id": agent_id,
                "agent_type": agent_config.get("type"),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_workflow_execution(
        self,
        workflow_id: str,
        workflow_steps: List[Dict[str, Any]],
        input_data: str,
        token: str
    ) -> bool:
        """Validate Superagent workflow execution.
        
        Args:
            workflow_id: Workflow identifier
            workflow_steps: List of workflow steps
            input_data: Input data for the workflow
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_workflow_execution",
                {"workflow_id": workflow_id},
                "WARNING"
            )
            return False

        context = {
            "workflow_id": workflow_id,
            "step_count": len(workflow_steps),
            "step_types": [step.get("type") for step in workflow_steps],
            "input_length": len(input_data),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "workflow_execution_validation",
            {
                "workflow_id": workflow_id,
                "step_count": len(workflow_steps),
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_tool_invocation(
        self,
        tool_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: str,
        token: str
    ) -> bool:
        """Validate Superagent tool invocation.
        
        Args:
            tool_id: Tool identifier
            tool_name: Name of the tool
            tool_args: Tool arguments
            agent_id: ID of the invoking agent
            token: Authentication token
            
        Returns:
            bool: True if invocation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_invocation",
                {"tool_id": tool_id, "tool_name": tool_name, "agent_id": agent_id},
                "WARNING"
            )
            return False

        context = {
            "tool_id": tool_id,
            "tool_name": tool_name,
            "tool_args_keys": list(tool_args.keys()),
            "agent_id": agent_id,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_invocation_validation",
            {
                "tool_id": tool_id,
                "tool_name": tool_name,
                "agent_id": agent_id,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_llm_call(
        self,
        agent_id: str,
        model: str,
        prompt: str,
        token: str
    ) -> bool:
        """Validate LLM API calls from Superagent.
        
        Args:
            agent_id: ID of the agent making the call
            model: Model name/identifier
            prompt: Prompt being sent
            token: Authentication token
            
        Returns:
            bool: True if call is allowed, False otherwise
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
            "prompt": prompt,
            "prompt_length": len(prompt),
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "llm_call_validation",
            {
                "agent_id": agent_id,
                "model": model,
                "prompt_preview": prompt[:100],
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_document_processing(
        self,
        document_id: str,
        document_type: str,
        document_size: int,
        processing_type: str,
        token: str
    ) -> bool:
        """Validate document processing in Superagent.
        
        Args:
            document_id: Document identifier
            document_type: Type of document (pdf, txt, etc.)
            document_size: Size of document in bytes
            processing_type: Type of processing (index, summarize, etc.)
            token: Authentication token
            
        Returns:
            bool: True if processing is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_document_processing",
                {"document_id": document_id, "document_type": document_type},
                "WARNING"
            )
            return False

        context = {
            "document_id": document_id,
            "document_type": document_type,
            "document_size": document_size,
            "processing_type": processing_type,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "document_processing_validation",
            {
                "document_id": document_id,
                "document_type": document_type,
                "processing_type": processing_type,
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
        """Wrap a Superagent agent with security validation.
        
        Args:
            agent_func: Original agent function
            agent_id: Agent identifier
            agent_config: Agent configuration
            token: Authentication token
            
        Returns:
            Callable: Secured agent function
        """
        def secured_agent(*args, **kwargs) -> Any:
            # Validate agent creation
            if not self.validate_agent_creation(agent_id, agent_config, token):
                self.security_monitor.record_event(
                    "agent_blocked",
                    {"agent_id": agent_id},
                    "ERROR"
                )
                raise PermissionError(f"Agent creation blocked: {agent_id}")

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

    def validate_api_key_usage(
        self,
        key_id: str,
        key_name: str,
        service: str,
        token: str
    ) -> bool:
        """Validate API key usage in Superagent.
        
        Args:
            key_id: API key identifier
            key_name: Name of the API key
            service: Service the key is for (openai, anthropic, etc.)
            token: Authentication token
            
        Returns:
            bool: True if usage is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_api_key_usage",
                {"key_id": key_id, "service": service},
                "WARNING"
            )
            return False

        context = {
            "key_id": key_id,
            "key_name": key_name,
            "service": service,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "superagent"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "api_key_usage_validation",
            {
                "key_id": key_id,
                "key_name": key_name,
                "service": service,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
