"""Tests for CrewAI Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.crewai_adapter import CrewAIAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestCrewAIAdapter(unittest.TestCase):
    """Test cases for CrewAIAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = CrewAIAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_action_success(self):
        """Test successful agent action validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {
            "sub": "test_agent",
            "type": "access"
        }
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_agent_action(
            agent_id="test_agent",
            action={"type": "execute_task", "resource": "operation"},
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_agent_action_invalid_token(self):
        """Test action validation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_agent_action(
            agent_id="test_agent",
            action={"type": "execute_task"},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_access_attempt",
            {"agent_id": "test_agent", "action": {"type": "execute_task"}},
            "WARNING"
        )

    def test_validate_agent_action_policy_denied(self):
        """Test action validation when policy denies access"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_agent_action(
            agent_id="test_agent",
            action={"type": "execute_task", "resource": "sensitive"},
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "action_validation",
            {
                "agent_id": "test_agent",
                "action": {"type": "execute_task", "resource": "sensitive"},
                "allowed": False
            },
            "WARNING"
        )

    def test_secure_task_execution_success(self):
        """Test successful secure task execution"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.secure_task_execution(
            task={"description": "Research task"},
            agent_id="test_agent",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_monitor.record_event.assert_called_with(
            "task_execution_attempt",
            {"task": {"description": "Research task"}, "agent_id": "test_agent", "allowed": True},
            "INFO"
        )

    def test_secure_task_execution_invalid_token(self):
        """Test task execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.secure_task_execution(
            task={"description": "Research task"},
            agent_id="test_agent",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "task_execution_failed",
            {"reason": "invalid_token", "agent_id": "test_agent"},
            "WARNING"
        )

    def test_validate_agent_communication_success(self):
        """Test successful agent-to-agent communication validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "source_agent"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="source_agent",
            target_agent="target_agent",
            message={"type": "request", "content": "Hello"},
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_agent_communication_denied(self):
        """Test agent communication when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "source_agent"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="source_agent",
            target_agent="target_agent",
            message={"type": "request"},
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
