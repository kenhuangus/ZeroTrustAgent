"""Tests for OpenAI Agent Adapter"""
import unittest
from unittest.mock import Mock, patch
from zta_agent.integrations.openai_agent_adapter import OpenAIAgentAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestOpenAIAgentAdapter(unittest.TestCase):
    """Test cases for OpenAIAgentAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = OpenAIAgentAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_creation_success(self):
        """Test successful agent creation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "creator"}
        self.mock_policy.evaluate.return_value = True

        agent_config = {
            "name": "TestAgent",
            "instructions": "Test instructions"
        }

        # Execute
        result = self.adapter.validate_agent_creation(agent_config, "valid_token")

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_agent_creation_invalid_token(self):
        """Test agent creation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_agent_creation({}, "invalid_token")

        # Assert
        self.assertFalse(result)

    def test_validate_tool_execution_success(self):
        """Test successful tool execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "agent"}
        self.mock_policy.evaluate.return_value = True

        tool_call = {
            "tool_name": "search",
            "arguments": {"query": "test"}
        }

        # Execute
        result = self.adapter.validate_tool_execution(tool_call, "valid_token")

        # Assert
        self.assertTrue(result)

    def test_validate_tool_execution_policy_denied(self):
        """Test tool execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "agent"}
        self.mock_policy.evaluate.return_value = False

        tool_call = {"tool_name": "dangerous_tool"}

        # Execute
        result = self.adapter.validate_tool_execution(tool_call, "valid_token")

        # Assert
        self.assertFalse(result)

    def test_secure_runner_execution_success(self):
        """Test successful runner execution"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "agent"}
        self.mock_policy.evaluate.return_value = True

        agent_config = {"name": "TestAgent"}
        user_input = "Hello"

        # Execute
        result = self.adapter.secure_runner_execution(
            agent_config, user_input, "valid_token"
        )

        # Assert
        self.assertTrue(result["allowed"])
        self.assertEqual(result["user_input"], user_input)

    def test_secure_runner_execution_invalid_input(self):
        """Test runner execution with invalid input"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "agent"}

        agent_config = {"name": "TestAgent"}
        malicious_input = "<script>alert('xss')</script>"

        # Execute
        result = self.adapter.secure_runner_execution(
            agent_config, malicious_input, "valid_token"
        )

        # Assert - should sanitize input
        self.assertTrue(result["allowed"])
        self.assertNotIn("<script>", result["user_input"])

    def test_validate_agent_handoff_success(self):
        """Test successful agent handoff validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "source_agent"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_agent_handoff(
            source_agent="source_agent",
            target_agent="target_agent",
            context={"task": "handoff"},
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)

    def test_create_secure_function_tool(self):
        """Test creating a secure function tool wrapper"""
        # Setup
        def sample_tool(x: int) -> int:
            return x * 2

        self.mock_auth.validate_token.return_value = {"sub": "agent"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        secure_tool = self.adapter.create_secure_function_tool(
            sample_tool, "valid_token"
        )

        # Assert
        self.assertIsNotNone(secure_tool)
        # The secure tool should wrap the original function


if __name__ == '__main__':
    unittest.main()
