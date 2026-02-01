""" Haystack Integration Adapter for Zero Trust Security Agent """
from typing import Any, Dict, Optional, List, Callable
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor


class HaystackAdapter:
    """Adapter for integrating Zero Trust Security with Haystack.
    
    Haystack is an end-to-end NLP framework for building search systems.
    This adapter provides security validation for:
    - Pipeline execution
    - Document store operations
    - Retriever queries
    - Generator/LLM calls
    - Component execution
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

    def validate_pipeline_execution(
        self,
        pipeline_name: str,
        pipeline_config: Dict[str, Any],
        query: str,
        token: str
    ) -> bool:
        """Validate Haystack pipeline execution.
        
        Args:
            pipeline_name: Name of the pipeline
            pipeline_config: Pipeline configuration
            query: Query being processed
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_pipeline_execution",
                {"pipeline_name": pipeline_name, "query_preview": query[:100]},
                "WARNING"
            )
            return False

        context = {
            "pipeline_name": pipeline_name,
            "pipeline_components": pipeline_config.get("components", []),
            "query": query,
            "query_length": len(query),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "pipeline_execution_validation",
            {
                "pipeline_name": pipeline_name,
                "query_preview": query[:100],
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_document_store_operation(
        self,
        store_name: str,
        operation: str,
        document_count: int,
        token: str
    ) -> bool:
        """Validate Haystack document store operations.
        
        Args:
            store_name: Name of the document store
            operation: Operation type (write, delete, update, get_all)
            document_count: Number of documents affected
            token: Authentication token
            
        Returns:
            bool: True if operation is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_document_store_operation",
                {"store_name": store_name, "operation": operation},
                "WARNING"
            )
            return False

        context = {
            "store_name": store_name,
            "operation": operation,
            "document_count": document_count,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "document_store_operation_validation",
            {
                "store_name": store_name,
                "operation": operation,
                "document_count": document_count,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_retriever_query(
        self,
        retriever_name: str,
        query: str,
        top_k: int,
        token: str
    ) -> bool:
        """Validate Haystack retriever queries.
        
        Args:
            retriever_name: Name of the retriever component
            query: Search query
            top_k: Number of results requested
            token: Authentication token
            
        Returns:
            bool: True if query is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_retriever_query",
                {"retriever_name": retriever_name, "query_preview": query[:100]},
                "WARNING"
            )
            return False

        context = {
            "retriever_name": retriever_name,
            "query": query,
            "top_k": top_k,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "retriever_query_validation",
            {
                "retriever_name": retriever_name,
                "query_preview": query[:100],
                "top_k": top_k,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_generator_call(
        self,
        generator_name: str,
        prompt: str,
        model: str,
        token: str
    ) -> bool:
        """Validate Haystack generator/LLM calls.
        
        Args:
            generator_name: Name of the generator component
            prompt: Prompt being sent to the generator
            model: Model name/identifier
            token: Authentication token
            
        Returns:
            bool: True if call is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_generator_call",
                {"generator_name": generator_name, "model": model},
                "WARNING"
            )
            return False

        context = {
            "generator_name": generator_name,
            "prompt": prompt,
            "prompt_length": len(prompt),
            "model": model,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "generator_call_validation",
            {
                "generator_name": generator_name,
                "model": model,
                "prompt_preview": prompt[:100],
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_component_execution(
        self,
        component_name: str,
        component_type: str,
        inputs: Dict[str, Any],
        token: str
    ) -> bool:
        """Validate Haystack component execution.
        
        Args:
            component_name: Name of the component
            component_type: Type of component (Reader, Ranker, etc.)
            inputs: Component inputs
            token: Authentication token
            
        Returns:
            bool: True if execution is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_component_execution",
                {"component_name": component_name, "component_type": component_type},
                "WARNING"
            )
            return False

        context = {
            "component_name": component_name,
            "component_type": component_type,
            "input_keys": list(inputs.keys()),
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "component_execution_validation",
            {
                "component_name": component_name,
                "component_type": component_type,
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def create_secure_pipeline(
        self,
        pipeline_func: Callable,
        pipeline_name: str,
        pipeline_config: Dict[str, Any],
        token: str
    ) -> Callable:
        """Wrap a Haystack pipeline with security validation.
        
        Args:
            pipeline_func: Original pipeline function
            pipeline_name: Name of the pipeline
            pipeline_config: Pipeline configuration
            token: Authentication token
            
        Returns:
            Callable: Secured pipeline function
        """
        def secured_pipeline(query: str, **kwargs) -> Any:
            # Validate pipeline execution
            if not self.validate_pipeline_execution(
                pipeline_name, pipeline_config, query, token
            ):
                self.security_monitor.record_event(
                    "pipeline_blocked",
                    {"pipeline_name": pipeline_name},
                    "ERROR"
                )
                raise PermissionError(f"Pipeline execution blocked: {pipeline_name}")

            # Execute the original pipeline
            try:
                result = pipeline_func(query, **kwargs)
                self.security_monitor.record_event(
                    "pipeline_execution_success",
                    {"pipeline_name": pipeline_name},
                    "INFO"
                )
                return result
            except Exception as e:
                self.security_monitor.record_event(
                    "pipeline_execution_error",
                    {"pipeline_name": pipeline_name, "error": str(e)},
                    "ERROR"
                )
                raise

        return secured_pipeline

    def validate_index_update(
        self,
        index_name: str,
        update_type: str,
        document_ids: List[str],
        token: str
    ) -> bool:
        """Validate Haystack index update operations.
        
        Args:
            index_name: Name of the index
            update_type: Type of update (add, delete, update_embeddings)
            document_ids: List of document IDs affected
            token: Authentication token
            
        Returns:
            bool: True if update is allowed, False otherwise
        """
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_index_update",
                {"index_name": index_name, "update_type": update_type},
                "WARNING"
            )
            return False

        context = {
            "index_name": index_name,
            "update_type": update_type,
            "document_count": len(document_ids),
            "document_ids": document_ids,
            "agent_id": claims.get("sub"),
            "claims": claims,
            "framework": "haystack"
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "index_update_validation",
            {
                "index_name": index_name,
                "update_type": update_type,
                "document_count": len(document_ids),
                "agent_id": claims.get("sub"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
