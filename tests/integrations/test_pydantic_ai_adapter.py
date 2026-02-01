"""Tests for Pydantic AI Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.pydantic_ai_adapter import PydanticAIAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestPydanticAIAdapter(unittest.TestCase):
    """Test cases for PydanticAIAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = PydanticAIAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_creation_success(self):
        """Test successful agent creation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_name="research_agent",
            model="gpt-4",
            result_type=str,
            deps_type=dict,
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

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_name="research_agent",
            model="gpt-4",
            result_type=None,
            deps_type=None,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_agent_creation",
            {"agent_name": "research_agent", "model": "gpt-4"},
            "WARNING"
        )

    def test_validate_agent_creation_policy_denied(self):
        """Test agent creation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_agent_creation(
            agent_name="admin_agent",
            model="gpt-4",
            result_type=str,
            deps_type=None,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_registration_success(self):
        """Test successful tool registration validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_tool_registration(
            tool_name="search_tool",
            tool_signature="(query: str) -> List[str]",
            agent_name="research_agent",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_tool_registration_invalid_token(self):
        """Test tool registration with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_tool_registration(
            tool_name="search_tool",
            tool_signature="(query: str) -> List[str]",
            agent_name="research_agent",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_registration_policy_denied(self):
        """Test tool registration when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_tool_registration(
            tool_name="dangerous_tool",
            tool_signature="(command: str) -> None",
            agent_name="research_agent",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_dependency_injection_success(self):
        """Test successful dependency injection validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_dependency_injection(
            agent_name="research_agent",
            dep_name="database",
            dep_type="DatabaseConnection",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_dependency_injection_invalid_token(self):
        """Test dependency injection with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_dependency_injection(
            agent_name="research_agent",
            dep_name="database",
            dep_type="DatabaseConnection",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_dependency_injection_policy_denied(self):
        """Test dependency injection when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_dependency_injection(
            agent_name="research_agent",
            dep_name="admin_database",
            dep_type="AdminDatabase",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_model_call_success(self):
        """Test successful model call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        prompt = "What is the capital of France?"

        # Execute
        result = self.adapter.validate_model_call(
            agent_name="research_agent",
            model="gpt-4",
            prompt=prompt,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_model_call_invalid_token(self):
        """Test model call with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_model_call(
            agent_name="research_agent",
            model="gpt-4",
            prompt="test prompt",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_model_call_policy_denied(self):
        """Test model call when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_model_call(
            agent_name="research_agent",
            model="gpt-4-turbo",
            prompt="expensive request",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_result_type_success(self):
        """Test successful result type validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_result_type(
            agent_name="research_agent",
            result_type=str,
            validation_result=True,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_result_type_invalid_token(self):
        """Test result type with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_result_type(
            agent_name="research_agent",
            result_type=str,
            validation_result=True,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_result_type_policy_denied(self):
        """Test result type when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_result_type(
            agent_name="research_agent",
            result_type=dict,
            validation_result=False,
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

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            mock_agent,
            agent_name="research_agent",
            model="gpt-4",
            token="valid_token"
        )

        # Execute the secured agent
        result = secured_agent()

        # Assert
        self.assertEqual(result, "Agent result")
        self.mock_monitor.record_event.assert_any_call(
            "agent_execution_success",
            {"agent_name": "research_agent"},
            "INFO"
        )

    def test_create_secure_agent_blocked(self):
        """Test secure agent wrapper blocks unauthorized creation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_agent():
            return "Agent result"

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            mock_agent,
            agent_name="restricted_agent",
            model="gpt-4",
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

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            failing_agent,
            agent_name="failing_agent",
            model="gpt-4",
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_agent()

        self.assertEqual(str(context.exception), "Agent execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "agent_execution_error",
            {"agent_name": "failing_agent", "error": "Agent execution failed"},
            "ERROR"
        )

    def test_validate_context_access_success(self):
        """Test successful context access validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_context_access(
            agent_name="research_agent",
            context_key="user_preferences",
            access_type="read",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_context_access_invalid_token(self):
        """Test context access with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_context_access(
            agent_name="research_agent",
            context_key="user_preferences",
            access_type="read",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_context_access_write_denied(self):
        """Test context write access when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "regular_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_context_access(
            agent_name="research_agent",
            context_key="system_config",
            access_type="write",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
