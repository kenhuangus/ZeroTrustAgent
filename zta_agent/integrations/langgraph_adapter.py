""" LangGraph Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class LangGraphAdapter:
    """Adapter for integrating Zero Trust Security with LangGraph workflows.
    
    LangGraph is a library for building stateful, multi-agent applications with LLMs.
    This adapter provides security validation for:
    - Node execution in the graph
    - State transitions between nodes
    - Tool calls within nodes
    - Agent-to-agent communication in multi-agent graphs
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

    def validate_node_execution(
        self,
        node_id: str,
        state: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate if a node is allowed to execute in the LangGraph workflow.
        
        Args:
            node_id: Identifier for the node being executed
            state: Current state of the graph
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_node_execution",
                {"node_id": node_id, "state_keys": list(state.keys())},
                "WARNING"
            )
            return False

        # Create context for policy evaluation
        context = {
            "node_id": node_id,
            "state_keys": list(state.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "langgraph"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record the execution attempt
        self.security_monitor.record_event(
            "node_execution_validation",
            {
                "node_id": node_id,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_state_transition(
        self,
        from_node: str,
        to_node: str,
        state: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate if a state transition between nodes is allowed.
        
        Args:
            from_node: Source node identifier
            to_node: Target node identifier
            state: Current state being transitioned
            token: Authentication token
            
        Returns:
            bool: True if transition is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_state_transition",
                {"from_node": from_node, "to_node": to_node},
                "WARNING"
            )
            return False

        context = {
            "from_node": from_node,
            "to_node": to_node,
            "state_keys": list(state.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "langgraph"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "state_transition_validation",
            {
                "from_node": from_node,
                "to_node": to_node,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        node_id: str,
        token: str
    ) -> bool:
        """Validate if a tool call within a node is allowed.
        
        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            node_id: Node where the tool is being called
            token: Authentication token
            
        Returns:
            bool: True if tool call is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_call",
                {"tool_name": tool_name, "node_id": node_id},
                "WARNING"
            )
            return False

        context = {
            "tool_name": tool_name,
            "tool_args_keys": list(tool_args.keys()),
            "node_id": node_id,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "langgraph"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_call_validation",
            {
                "tool_name": tool_name,
                "node_id": node_id,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_node(
        self,
        node_func: Callable,
        node_id: str,
        token: str
    ) -> Callable:
        """Wrap a LangGraph node function with security validation.
        
        Args:
            node_func: Original node function to wrap
            node_id: Identifier for the node
            token: Authentication token
            
        Returns:
            Callable: Secured node function
        """
        def secured_node(state: Dict[str, Any]) -> Dict[str, Any]:
            # Validate node execution
            if not self.validate_node_execution(node_id, state, token):
                self.security_monitor.record_event(
                    "node_execution_blocked",
                    {"node_id": node_id},
                    "ERROR"
                )
                raise PermissionError(f"Node execution blocked: {node_id}")

            # Execute the original node function
            try:
                result = node_func(state)
                self.security_monitor.record_event(
                    "node_execution_success",
                    {"node_id": node_id},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "node_execution_error",
                    {"node_id": node_id, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_node

    def validate_agent_communication(
        self,
        source_agent: str,
        target_agent: str,
        message: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate agent-to-agent communication in multi-agent LangGraph workflows.
        
        Args:
            source_agent: Source agent identifier
            target_agent: Target agent identifier
            message: Message being sent
            token: Authentication token
            
        Returns:
            bool: True if communication is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        context = {
            "source_agent": source_agent,
            "target_agent": target_agent,
            "message_type": message.get("type"),
            "claims": claims,
            "framework": "langgraph"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_communication",
            {
                "source_agent": source_agent,
                "target_agent": target_agent,
                "message_type": message.get("type"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def secure_graph_execution(
        self,
        graph_config: Dict[str, Any],
        initial_state: Dict[str, Any],
        token: str
    ) -> Dict[str, Any]:
        """Validate and secure the execution of a complete LangGraph workflow.
        
        Args:
            graph_config: Configuration for the graph
            initial_state: Initial state for the graph
            token: Authentication token
            
        Returns:
            Dict containing execution result and security status
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return {
                "allowed": False,
                "error": "Invalid authentication token"
            }

        context = {
            "graph_nodes": graph_config.get("nodes", []),
            "graph_edges": graph_config.get("edges", []),
            "initial_state_keys": list(initial_state.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "langgraph"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "graph_execution_validation",
            {
                "graph_nodes": graph_config.get("nodes", []),
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return {
            "allowed": is_allowed,
            "agent_id": claims.get("sub"),
            "graph_config": graph_config if is_allowed else None
        }
