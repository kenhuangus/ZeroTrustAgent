"""Tests for AutoGen Adapter"""
import unittest
from unittest.mock import Mock
from zta_agent.integrations.autogen_adapter import AutoGenAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestAutoGenAdapter(unittest.TestCase):
    """Test cases for AutoGenAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = AutoGenAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_communication_success(self):
        """Test successful agent communication validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "assistant"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="assistant",
            target_agent="user",
            message={"type": "text", "content": "Hello"},
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_agent_communication_invalid_token(self):
        """Test communication with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="assistant",
            target_agent="user",
            message={"type": "text"},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_agent_communication_policy_denied(self):
        """Test communication when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "assistant"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="assistant",
            target_agent="user",
            message={"type": "text"},
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
