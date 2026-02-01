"""Tests for Haystack Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.haystack_adapter import HaystackAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestHaystackAdapter(unittest.TestCase):
    """Test cases for HaystackAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = HaystackAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_pipeline_execution_success(self):
        """Test successful pipeline execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        pipeline_config = {
            "components": ["Retriever", "Reader", "Generator"]
        }

        # Execute
        result = self.adapter.validate_pipeline_execution(
            pipeline_name="search_pipeline",
            pipeline_config=pipeline_config,
            query="What is machine learning?",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_pipeline_execution_invalid_token(self):
        """Test pipeline execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        pipeline_config = {"components": ["Retriever"]}

        # Execute
        result = self.adapter.validate_pipeline_execution(
            pipeline_name="search_pipeline",
            pipeline_config=pipeline_config,
            query="test query",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_pipeline_execution",
            {"pipeline_name": "search_pipeline", "query_preview": "test query"},
            "WARNING"
        )

    def test_validate_pipeline_execution_policy_denied(self):
        """Test pipeline execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        pipeline_config = {"components": ["AdminComponent"]}

        # Execute
        result = self.adapter.validate_pipeline_execution(
            pipeline_name="admin_pipeline",
            pipeline_config=pipeline_config,
            query="sensitive query",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_document_store_operation_success(self):
        """Test successful document store operation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_document_store_operation(
            store_name="document_store",
            operation="write",
            document_count=10,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_document_store_operation_delete_denied(self):
        """Test document store delete operation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "regular_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_document_store_operation(
            store_name="production_store",
            operation="delete",
            document_count=100,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_document_store_operation_invalid_token(self):
        """Test document store operation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_document_store_operation(
            store_name="document_store",
            operation="write",
            document_count=5,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_retriever_query_success(self):
        """Test successful retriever query validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_retriever_query(
            retriever_name="BM25Retriever",
            query="machine learning algorithms",
            top_k=10,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_retriever_query_invalid_token(self):
        """Test retriever query with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_retriever_query(
            retriever_name="BM25Retriever",
            query="test query",
            top_k=5,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_retriever_query_policy_denied(self):
        """Test retriever query when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_retriever_query(
            retriever_name="SensitiveRetriever",
            query="confidential data",
            top_k=100,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_generator_call_success(self):
        """Test successful generator call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        prompt = "Summarize the following document: ..."

        # Execute
        result = self.adapter.validate_generator_call(
            generator_name="OpenAIGenerator",
            prompt=prompt,
            model="gpt-4",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_generator_call_invalid_token(self):
        """Test generator call with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_generator_call(
            generator_name="OpenAIGenerator",
            prompt="test prompt",
            model="gpt-4",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_generator_call_policy_denied(self):
        """Test generator call when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_generator_call(
            generator_name="ExpensiveGenerator",
            prompt="generate code",
            model="gpt-4-turbo",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_component_execution_success(self):
        """Test successful component execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        inputs = {"query": "test", "documents": []}

        # Execute
        result = self.adapter.validate_component_execution(
            component_name="reader_1",
            component_type="Reader",
            inputs=inputs,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_component_execution_invalid_token(self):
        """Test component execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_component_execution(
            component_name="reader_1",
            component_type="Reader",
            inputs={},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_component_execution_policy_denied(self):
        """Test component execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_component_execution(
            component_name="admin_component",
            component_type="AdminTool",
            inputs={"command": "delete"},
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_pipeline_success(self):
        """Test creating a secure pipeline wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def mock_pipeline(query, **kwargs):
            return {"results": [f"Result for: {query}"]}

        pipeline_config = {"components": ["Retriever", "Reader"]}

        # Execute
        secured_pipeline = self.adapter.create_secure_pipeline(
            mock_pipeline,
            pipeline_name="search_pipeline",
            pipeline_config=pipeline_config,
            token="valid_token"
        )

        # Execute the secured pipeline
        result = secured_pipeline("test query")

        # Assert
        self.assertEqual(result, {"results": ["Result for: test query"]})
        self.mock_monitor.record_event.assert_any_call(
            "pipeline_execution_success",
            {"pipeline_name": "search_pipeline"},
            "INFO"
        )

    def test_create_secure_pipeline_blocked(self):
        """Test secure pipeline wrapper blocks unauthorized execution"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_pipeline(query, **kwargs):
            return {"results": []}

        pipeline_config = {"components": ["RestrictedComponent"]}

        # Execute
        secured_pipeline = self.adapter.create_secure_pipeline(
            mock_pipeline,
            pipeline_name="restricted_pipeline",
            pipeline_config=pipeline_config,
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_pipeline("test query")

        self.assertIn("restricted_pipeline", str(context.exception))

    def test_create_secure_pipeline_handles_errors(self):
        """Test secure pipeline wrapper handles pipeline errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def failing_pipeline(query, **kwargs):
            raise RuntimeError("Pipeline execution failed")

        pipeline_config = {"components": ["Retriever"]}

        # Execute
        secured_pipeline = self.adapter.create_secure_pipeline(
            failing_pipeline,
            pipeline_name="failing_pipeline",
            pipeline_config=pipeline_config,
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_pipeline("test query")

        self.assertEqual(str(context.exception), "Pipeline execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "pipeline_execution_error",
            {"pipeline_name": "failing_pipeline", "error": "Pipeline execution failed"},
            "ERROR"
        )

    def test_validate_index_update_success(self):
        """Test successful index update validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        document_ids = ["doc_1", "doc_2", "doc_3"]

        # Execute
        result = self.adapter.validate_index_update(
            index_name="main_index",
            update_type="add",
            document_ids=document_ids,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_index_update_invalid_token(self):
        """Test index update with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_index_update(
            index_name="main_index",
            update_type="add",
            document_ids=["doc_1"],
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_index_update_delete_denied(self):
        """Test index delete operation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "regular_user"}
        self.mock_policy.evaluate.return_value = False

        document_ids = ["doc_1", "doc_2"]

        # Execute
        result = self.adapter.validate_index_update(
            index_name="production_index",
            update_type="delete",
            document_ids=document_ids,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
