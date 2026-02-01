""" Semantic Kernel Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class SemanticKernelAdapter:
    """Adapter for integrating Zero Trust Security with Microsoft Semantic Kernel.
    
    Semantic Kernel is an SDK that integrates Large Language Models (LLMs) with
    conventional programming languages. This adapter provides security validation for:
    - Kernel function execution
    - Plugin operations
    - Planner execution
    - Memory store access
    - Prompt rendering
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

    def validate_kernel_function(
        self,
        function_name: str,
        function_args: Dict[str, Any],
        plugin_name: Optional[str],
        token: str
    ) -> bool:
        """Validate if a Semantic Kernel function can be executed.
        
        Args:
            function_name: Name of the kernel function
            function_args: Arguments passed to the function
            plugin_name: Optional plugin name containing the function
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_kernel_function",
                {
                    "function_name": function_name,
                    "plugin_name": plugin_name
                },
                "WARNING"
            )
            return False

        # Create context for policy evaluation
        context = {
            "function_name": function_name,
            "function_args_keys": list(function_args.keys()),
            "plugin_name": plugin_name,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record the function execution attempt
        self.security_monitor.record_event(
            "kernel_function_validation",
            {
                "function_name": function_name,
                "plugin_name": plugin_name,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_plugin_access(
        self,
        plugin_name: str,
        operation: str,
        token: str
    ) -> bool:
        """Validate access to a Semantic Kernel plugin.
        
        Args:
            plugin_name: Name of the plugin
            operation: Operation being performed (load, execute, etc.)
            token: Authentication token
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_plugin_access",
                {"plugin_name": plugin_name, "operation": operation},
                "WARNING"
            )
            return False

        context = {
            "plugin_name": plugin_name,
            "operation": operation,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "plugin_access_validation",
            {
                "plugin_name": plugin_name,
                "operation": operation,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_planner_execution(
        self,
        planner_name: str,
        goal: str,
        available_functions: List[str],
        token: str
    ) -> bool:
        """Validate Semantic Kernel planner execution.
        
        Args:
            planner_name: Name/type of planner (Basic, Stepwise, etc.)
            goal: The goal/plan description
            available_functions: List of functions the planner can use
            token: Authentication token
            
        Returns:
            bool: True if planner execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_planner_execution",
                {"planner_name": planner_name, "goal_preview": goal[:100]},
                "WARNING"
            )
            return False

        context = {
            "planner_name": planner_name,
            "goal": goal,
            "available_functions": available_functions,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "planner_execution_validation",
            {
                "planner_name": planner_name,
                "available_functions": available_functions,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_memory_access(
        self,
        collection_name: str,
        operation: str,
        token: str
    ) -> bool:
        """Validate access to Semantic Kernel memory store.
        
        Args:
            collection_name: Name of the memory collection
            operation: Operation type (save, retrieve, search, delete)
            token: Authentication token
            
        Returns:
            bool: True if memory access is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_memory_access",
                {"collection_name": collection_name, "operation": operation},
                "WARNING"
            )
            return False

        context = {
            "collection_name": collection_name,
            "operation": operation,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "memory_access_validation",
            {
                "collection_name": collection_name,
                "operation": operation,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_prompt_render(
        self,
        prompt_template: str,
        variables: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate prompt template rendering.
        
        Args:
            prompt_template: The prompt template being rendered
            variables: Variables being injected into the prompt
            token: Authentication token
            
        Returns:
            bool: True if prompt rendering is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_prompt_render",
                {"prompt_preview": prompt_template[:100]},
                "WARNING"
            )
            return False

        context = {
            "prompt_template": prompt_template,
            "variable_keys": list(variables.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "prompt_render_validation",
            {
                "prompt_preview": prompt_template[:100],
                "variable_keys": list(variables.keys()),
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_kernel_function(
        self,
        func: Callable,
        function_name: str,
        plugin_name: Optional[str],
        token: str
    ) -> Callable:
        """Wrap a Semantic Kernel function with security validation.
        
        Args:
            func: Original kernel function to wrap
            function_name: Name of the function
            plugin_name: Optional plugin name
            token: Authentication token
            
        Returns:
            Callable: Secured kernel function
        """
        def secured_function(**kwargs) -> Any:
            # Validate function execution
            if not self.validate_kernel_function(
                function_name, kwargs, plugin_name, token
            ):
                self.security_monitor.record_event(
                    "kernel_function_blocked",
                    {
                        "function_name": function_name,
                        "plugin_name": plugin_name
                    },
                    "ERROR"
                )
                raise PermissionError(
                    f"Kernel function blocked: {plugin_name}.{function_name}"
                    if plugin_name else f"Kernel function blocked: {function_name}"
                )

            # Execute the original function
            try:
                result = func(**kwargs)
                self.security_monitor.record_event(
                    "kernel_function_success",
                    {
                        "function_name": function_name,
                        "plugin_name": plugin_name
                    },
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "kernel_function_error",
                    {
                        "function_name": function_name,
                        "plugin_name": plugin_name,
                        "error": str(e)
                    },
                    "ERROR"
                )
                raise

        return secured_function

    def validate_chat_completion(
        self,
        chat_history: List[Dict[str, str]],
        settings: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate chat completion requests.
        
        Args:
            chat_history: List of chat messages
            settings: Completion settings (temperature, max_tokens, etc.)
            token: Authentication token
            
        Returns:
            bool: True if chat completion is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_chat_completion",
                {"message_count": len(chat_history)},
                "WARNING"
            )
            return False

        context = {
            "message_count": len(chat_history),
            "settings": settings,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "semantic_kernel"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "chat_completion_validation",
            {
                "message_count": len(chat_history),
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
