"""Tests for Superagent Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.superagent_adapter import SuperagentAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestSuperagentAdapter(unittest.TestCase):
    """Test cases for SuperagentAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = SuperagentAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_creation_success(self):
        """Test successful agent creation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        agent_config = {
            "type": "assistant",
            "llm": "gpt-4",
            "tools": ["search", "calculator"]
        }

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_id="agent_1",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_agent_creation_invalid_token(self):
        """Test agent creation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        agent_config = {"type": "assistant"}

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_id="agent_1",
            agent_config=agent_config,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_agent_creation",
            {"agent_id": "agent_1", "agent_type": "assistant"},
            "WARNING"
        )

    def test_validate_agent_creation_policy_denied(self):
        """Test agent creation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        agent_config = {
            "type": "admin",
            "llm": "gpt-4",
            "tools": ["delete", "modify"]
        }

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_id="admin_agent",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_workflow_execution_success(self):
        """Test successful workflow execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        workflow_steps = [
            {"type": "llm", "config": {}},
            {"type": "tool", "config": {}}
        ]

        # Execute
        result = self.adapter.validate_workflow_execution(
            workflow_id="workflow_1",
            workflow_steps=workflow_steps,
            input_data="Process this data",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_workflow_execution_invalid_token(self):
        """Test workflow execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        workflow_steps = [{"type": "llm"}]

        # Execute
        result = self.adapter.validate_workflow_execution(
            workflow_id="workflow_1",
            workflow_steps=workflow_steps,
            input_data="test",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_workflow_execution_policy_denied(self):
        """Test workflow execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        workflow_steps = [
            {"type": "dangerous_tool"},
            {"type": "admin_action"}
        ]

        # Execute
        result = self.adapter.validate_workflow_execution(
            workflow_id="restricted_workflow",
            workflow_steps=workflow_steps,
            input_data="sensitive data",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_invocation_success(self):
        """Test successful tool invocation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        tool_args = {"query": "search term"}

        # Execute
        result = self.adapter.validate_tool_invocation(
            tool_id="tool_1",
            tool_name="search_tool",
            tool_args=tool_args,
            agent_id="agent_1",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_tool_invocation_invalid_token(self):
        """Test tool invocation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_tool_invocation(
            tool_id="tool_1",
            tool_name="search_tool",
            tool_args={},
            agent_id="agent_1",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_invocation_policy_denied(self):
        """Test tool invocation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        tool_args = {"command": "delete_all"}

        # Execute
        result = self.adapter.validate_tool_invocation(
            tool_id="tool_1",
            tool_name="dangerous_tool",
            tool_args=tool_args,
            agent_id="agent_1",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_llm_call_success(self):
        """Test successful LLM call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        prompt = "What is machine learning?"

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4",
            prompt=prompt,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_llm_call_invalid_token(self):
        """Test LLM call with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4",
            prompt="test",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_llm_call_policy_denied(self):
        """Test LLM call when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4-turbo",
            prompt="expensive request",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_document_processing_success(self):
        """Test successful document processing validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_document_processing(
            document_id="doc_1",
            document_type="pdf",
            document_size=1024000,
            processing_type="index",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_document_processing_invalid_token(self):
        """Test document processing with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_document_processing(
            document_id="doc_1",
            document_type="pdf",
            document_size=1024,
            processing_type="index",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_document_processing_policy_denied(self):
        """Test document processing when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_document_processing(
            document_id="doc_1",
            document_type="exe",
            document_size=1024000,
            processing_type="execute",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_agent_success(self):
        """Test creating a secure agent wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def mock_agent():
            return "Agent result"

        agent_config = {"type": "assistant"}

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            mock_agent,
            agent_id="agent_1",
            agent_config=agent_config,
            token="valid_token"
        )

        # Execute the secured agent
        result = secured_agent()

        # Assert
        self.assertEqual(result, "Agent result")
        self.mock_monitor.record_event.assert_any_call(
            "agent_execution_success",
            {"agent_id": "agent_1"},
            "INFO"
        )

    def test_create_secure_agent_blocked(self):
        """Test secure agent wrapper blocks unauthorized creation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_agent():
            return "Agent result"

        agent_config = {"type": "restricted"}

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            mock_agent,
            agent_id="restricted_agent",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_agent()

        self.assertIn("restricted_agent", str(context.exception))

    def test_create_secure_agent_handles_errors(self):
        """Test secure agent wrapper handles agent errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def failing_agent():
            raise RuntimeError("Agent execution failed")

        agent_config = {"type": "assistant"}

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            failing_agent,
            agent_id="failing_agent",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_agent()

        self.assertEqual(str(context.exception), "Agent execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "agent_execution_error",
            {"agent_id": "failing_agent", "error": "Agent execution failed"},
            "ERROR"
        )

    def test_validate_api_key_usage_success(self):
        """Test successful API key usage validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_api_key_usage(
            key_id="key_1",
            key_name="OpenAI Key",
            service="openai",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_api_key_usage_invalid_token(self):
        """Test API key usage with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_api_key_usage(
            key_id="key_1",
            key_name="OpenAI Key",
            service="openai",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_api_key_usage_policy_denied(self):
        """Test API key usage when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_api_key_usage(
            key_id="admin_key",
            key_name="Admin Key",
            service="admin_api",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
