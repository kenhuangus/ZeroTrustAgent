"""Tests for LlamaIndex Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.llama_index_adapter import LlamaIndexAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestLlamaIndexAdapter(unittest.TestCase):
    """Test cases for LlamaIndexAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = LlamaIndexAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_query_success(self):
        """Test successful query validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_query(
            query="What is the capital of France?",
            index_id="knowledge_base",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_query_invalid_token(self):
        """Test query with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_query(
            query="What is the capital?",
            index_id="knowledge_base",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_query_attempt",
            {"query": "What is the capital?", "index_id": "knowledge_base"},
            "WARNING"
        )

    def test_validate_query_policy_denied(self):
        """Test query when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_query(
            query="sensitive query",
            index_id="restricted_index",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "query_validation",
            {
                "query_preview": "sensitive query",
                "index_id": "restricted_index",
                "agent_id": "test_user",
                "allowed": False
            },
            "WARNING"
        )

    def test_validate_retriever_access_success(self):
        """Test successful retriever access validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_retriever_access(
            retriever_id="doc_retriever",
            query="find documents",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_retriever_access_invalid_token(self):
        """Test retriever access with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_retriever_access(
            retriever_id="doc_retriever",
            query="find documents",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_document_ingestion_success(self):
        """Test successful document ingestion validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        document_metadata = {
            "type": "pdf",
            "size": 1024
        }

        # Execute
        result = self.adapter.validate_document_ingestion(
            document_id="doc_123",
            document_metadata=document_metadata,
            index_id="knowledge_base",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_document_ingestion_policy_denied(self):
        """Test document ingestion when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        document_metadata = {"type": "executable"}

        # Execute
        result = self.adapter.validate_document_ingestion(
            document_id="malicious_doc",
            document_metadata=document_metadata,
            index_id="knowledge_base",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_call_success(self):
        """Test successful tool call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        tool_args = {"query": "search term"}

        # Execute
        result = self.adapter.validate_tool_call(
            tool_name="search_tool",
            tool_args=tool_args,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_tool_call_invalid_token(self):
        """Test tool call with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_tool_call(
            tool_name="search_tool",
            tool_args={},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_query_engine_success(self):
        """Test creating a secure query engine wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def mock_query_func(query, **kwargs):
            return {"result": f"Answer to: {query}"}

        # Execute
        secured_query = self.adapter.create_secure_query_engine(
            mock_query_func,
            index_id="knowledge_base",
            token="valid_token"
        )

        # Execute the secured query
        result = secured_query("What is AI?")

        # Assert
        self.assertEqual(result, {"result": "Answer to: What is AI?"})
        self.mock_monitor.record_event.assert_any_call(
            "query_success",
            {"index_id": "knowledge_base"},
            "INFO"
        )

    def test_create_secure_query_engine_blocked(self):
        """Test secure query engine blocks unauthorized queries"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_query_func(query, **kwargs):
            return {"result": f"Answer to: {query}"}

        # Execute
        secured_query = self.adapter.create_secure_query_engine(
            mock_query_func,
            index_id="restricted_index",
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_query("sensitive query")

        self.assertIn("restricted_index", str(context.exception))

    def test_create_secure_query_engine_handles_errors(self):
        """Test secure query engine handles query function errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def failing_query_func(query, **kwargs):
            raise RuntimeError("Query execution failed")

        # Execute
        secured_query = self.adapter.create_secure_query_engine(
            failing_query_func,
            index_id="knowledge_base",
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_query("test query")

        self.assertEqual(str(context.exception), "Query execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "query_error",
            {"index_id": "knowledge_base", "error": "Query execution failed"},
            "ERROR"
        )

    def test_validate_agent_runner_success(self):
        """Test successful agent runner validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        tools = ["search", "calculator"]

        # Execute
        result = self.adapter.validate_agent_runner(
            agent_id="research_agent",
            task="Research quantum computing",
            tools=tools,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_agent_runner_invalid_token(self):
        """Test agent runner with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_agent_runner(
            agent_id="research_agent",
            task="Research task",
            tools=["search"],
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_agent_runner_policy_denied(self):
        """Test agent runner when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_agent_runner(
            agent_id="admin_agent",
            task="administrative task",
            tools=["delete", "modify"],
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_index_operation_success(self):
        """Test successful index operation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "admin_user"}
        self.mock_policy.evaluate.return_value = True

        parameters = {"schema": "default"}

        # Execute
        result = self.adapter.validate_index_operation(
            operation="create",
            index_id="new_index",
            parameters=parameters,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_index_operation_delete_denied(self):
        """Test index delete operation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "regular_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_index_operation(
            operation="delete",
            index_id="production_index",
            parameters={},
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_index_operation_invalid_token(self):
        """Test index operation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_index_operation(
            operation="create",
            index_id="test_index",
            parameters={},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
