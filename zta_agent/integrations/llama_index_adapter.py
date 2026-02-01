""" LlamaIndex Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class LlamaIndexAdapter:
    """Adapter for integrating Zero Trust Security with LlamaIndex.
    
    LlamaIndex is a data framework for LLM applications to ingest, structure, and access
    private or domain-specific data. This adapter provides security validation for:
    - Query engine execution
    - Retriever access
    - Document ingestion
    - Tool/Agent runner operations
    - Index operations
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

    def validate_query(
        self,
        query: str,
        index_id: str,
        token: str
    ) -> bool:
        """Validate if a query to a LlamaIndex index is allowed.
        
        Args:
            query: The query string
            index_id: Identifier for the index being queried
            token: Authentication token
            
        Returns:
            bool: True if query is allowed, False otherwise
        """
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_query_attempt",
                {"query": query[:100], "index_id": index_id},
                "WARNING"
            )
            return False

        # Create context for policy evaluation
        context = {
            "query": query,
            "query_length": len(query),
            "index_id": index_id,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)

        # Record the query attempt
        self.security_monitor.record_event(
            "query_validation",
            {
                "query_preview": query[:100],
                "index_id": index_id,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_retriever_access(
        self,
        retriever_id: str,
        query: str,
        token: str
    ) -> bool:
        """Validate access to a LlamaIndex retriever.
        
        Args:
            retriever_id: Identifier for the retriever
            query: The retrieval query
            token: Authentication token
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_retriever_access",
                {"retriever_id": retriever_id},
                "WARNING"
            )
            return False

        context = {
            "retriever_id": retriever_id,
            "query": query,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "retriever_access_validation",
            {
                "retriever_id": retriever_id,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_document_ingestion(
        self,
        document_id: str,
        document_metadata: Dict[str, Any],
        index_id: str,
        token: str
    ) -> bool:
        """Validate if document ingestion is allowed.
        
        Args:
            document_id: Identifier for the document
            document_metadata: Metadata about the document
            index_id: Target index for ingestion
            token: Authentication token
            
        Returns:
            bool: True if ingestion is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_document_ingestion",
                {"document_id": document_id, "index_id": index_id},
                "WARNING"
            )
            return False

        context = {
            "document_id": document_id,
            "document_type": document_metadata.get("type"),
            "document_size": document_metadata.get("size"),
            "index_id": index_id,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "document_ingestion_validation",
            {
                "document_id": document_id,
                "index_id": index_id,
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
        token: str
    ) -> bool:
        """Validate a tool call in LlamaIndex agent/chain.
        
        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            token: Authentication token
            
        Returns:
            bool: True if tool call is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_tool_call",
                {"tool_name": tool_name},
                "WARNING"
            )
            return False

        context = {
            "tool_name": tool_name,
            "tool_args_keys": list(tool_args.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "tool_call_validation",
            {
                "tool_name": tool_name,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_query_engine(
        self,
        query_func: Callable,
        index_id: str,
        token: str
    ) -> Callable:
        """Wrap a LlamaIndex query function with security validation.
        
        Args:
            query_func: Original query function to wrap
            index_id: Identifier for the index
            token: Authentication token
            
        Returns:
            Callable: Secured query function
        """
        def secured_query(query: str, **kwargs) -> Any:
            # Validate query
            if not self.validate_query(query, index_id, token):
                self.security_monitor.record_event(
                    "query_blocked",
                    {"query_preview": query[:100], "index_id": index_id},
                    "ERROR"
                )
                raise PermissionError(f"Query blocked for index: {index_id}")

            # Execute the original query function
            try:
                result = query_func(query, **kwargs)
                self.security_monitor.record_event(
                    "query_success",
                    {"index_id": index_id},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "query_error",
                    {"index_id": index_id, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_query

    def validate_agent_runner(
        self,
        agent_id: str,
        task: str,
        tools: List[str],
        token: str
    ) -> bool:
        """Validate LlamaIndex agent runner execution.
        
        Args:
            agent_id: Identifier for the agent
            task: Task description
            tools: List of tools the agent will use
            token: Authentication token
            
        Returns:
            bool: True if agent execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_agent_execution",
                {"agent_id": agent_id, "task_preview": task[:100]},
                "WARNING"
            )
            return False

        context = {
            "agent_id": agent_id,
            "task": task,
            "tools": tools,
            "user_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "agent_runner_validation",
            {
                "agent_id": agent_id,
                "tools": tools,
                "user_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_index_operation(
        self,
        operation: str,
        index_id: str,
        parameters: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate index-level operations (create, delete, update).
        
        Args:
            operation: Type of operation (create, delete, update, etc.)
            index_id: Target index identifier
            parameters: Operation parameters
            token: Authentication token
            
        Returns:
            bool: True if operation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_index_operation",
                {"operation": operation, "index_id": index_id},
                "WARNING"
            )
            return False

        context = {
            "operation": operation,
            "index_id": index_id,
            "parameters": parameters,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "llama_index"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "index_operation_validation",
            {
                "operation": operation,
                "index_id": index_id,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
