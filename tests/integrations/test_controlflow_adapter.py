"""Tests for ControlFlow Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.controlflow_adapter import ControlFlowAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestControlFlowAdapter(unittest.TestCase):
    """Test cases for ControlFlowAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = ControlFlowAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_flow_creation_success(self):
        """Test successful flow creation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        flow_config = {
            "name": "data_processing_flow",
            "tasks": [{"id": "task1"}, {"id": "task2"}],
            "agents": [{"id": "agent1"}]
        }

        # Execute
        result = self.adapter.validate_flow_creation(
            flow_id="flow_1",
            flow_config=flow_config,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_flow_creation_invalid_token(self):
        """Test flow creation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        flow_config = {"name": "test_flow"}

        # Execute
        result = self.adapter.validate_flow_creation(
            flow_id="flow_1",
            flow_config=flow_config,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_flow_creation",
            {"flow_id": "flow_1"},
            "WARNING"
        )

    def test_validate_flow_creation_policy_denied(self):
        """Test flow creation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        flow_config = {
            "name": "admin_flow",
            "tasks": [{"id": "admin_task"}]
        }

        # Execute
        result = self.adapter.validate_flow_creation(
            flow_id="admin_flow",
            flow_config=flow_config,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_flow_execution_success(self):
        """Test successful flow execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        input_data = {"query": "test data", "params": {}}

        # Execute
        result = self.adapter.validate_flow_execution(
            flow_id="flow_1",
            input_data=input_data,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_flow_execution_invalid_token(self):
        """Test flow execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_flow_execution(
            flow_id="flow_1",
            input_data={},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_flow_execution_policy_denied(self):
        """Test flow execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        input_data = {"sensitive": "data"}

        # Execute
        result = self.adapter.validate_flow_execution(
            flow_id="restricted_flow",
            input_data=input_data,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_task_creation_success(self):
        """Test successful task creation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        task_config = {
            "name": "process_data",
            "type": "llm",
            "agent": "agent_1"
        }

        # Execute
        result = self.adapter.validate_task_creation(
            task_id="task_1",
            task_config=task_config,
            flow_id="flow_1",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_task_creation_invalid_token(self):
        """Test task creation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        task_config = {"name": "test_task"}

        # Execute
        result = self.adapter.validate_task_creation(
            task_id="task_1",
            task_config=task_config,
            flow_id="flow_1",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_task_creation_policy_denied(self):
        """Test task creation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        task_config = {
            "name": "admin_task",
            "type": "admin_action"
        }

        # Execute
        result = self.adapter.validate_task_creation(
            task_id="admin_task",
            task_config=task_config,
            flow_id="flow_1",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_agent_registration_success(self):
        """Test successful agent registration validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        agent_config = {
            "name": "data_processor",
            "model": "gpt-4",
            "tools": ["search"]
        }

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="agent_1",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_agent_registration_invalid_token(self):
        """Test agent registration with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        agent_config = {"name": "test_agent"}

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="agent_1",
            agent_config=agent_config,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_agent_registration_policy_denied(self):
        """Test agent registration when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        agent_config = {
            "name": "admin_agent",
            "model": "gpt-4",
            "tools": ["delete", "modify"]
        }

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="admin_agent",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_usage_success(self):
        """Test successful tool usage validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        tool_args = {"query": "search term"}

        # Execute
        result = self.adapter.validate_tool_usage(
            tool_name="search_tool",
            tool_args=tool_args,
            agent_id="agent_1",
            task_id="task_1",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_tool_usage_invalid_token(self):
        """Test tool usage with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_tool_usage(
            tool_name="search_tool",
            tool_args={},
            agent_id="agent_1",
            task_id="task_1",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_usage_policy_denied(self):
        """Test tool usage when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        tool_args = {"command": "delete_all"}

        # Execute
        result = self.adapter.validate_tool_usage(
            tool_name="dangerous_tool",
            tool_args=tool_args,
            agent_id="agent_1",
            task_id="task_1",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_context_access_success(self):
        """Test successful context access validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_context_access(
            context_key="user_data",
            access_type="read",
            flow_id="flow_1",
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
            context_key="user_data",
            access_type="read",
            flow_id="flow_1",
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
            context_key="system_config",
            access_type="write",
            flow_id="flow_1",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_flow_success(self):
        """Test creating a secure flow wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def mock_flow():
            return "Flow result"

        flow_config = {"name": "test_flow"}

        # Execute
        secured_flow = self.adapter.create_secure_flow(
            mock_flow,
            flow_id="flow_1",
            flow_config=flow_config,
            token="valid_token"
        )

        # Execute the secured flow
        result = secured_flow()

        # Assert
        self.assertEqual(result, "Flow result")
        self.mock_monitor.record_event.assert_any_call(
            "flow_execution_success",
            {"flow_id": "flow_1"},
            "INFO"
        )

    def test_create_secure_flow_blocked(self):
        """Test secure flow wrapper blocks unauthorized creation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_flow():
            return "Flow result"

        flow_config = {"name": "restricted_flow"}

        # Execute
        secured_flow = self.adapter.create_secure_flow(
            mock_flow,
            flow_id="restricted_flow",
            flow_config=flow_config,
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_flow()

        self.assertIn("restricted_flow", str(context.exception))

    def test_create_secure_flow_handles_errors(self):
        """Test secure flow wrapper handles flow errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def failing_flow():
            raise RuntimeError("Flow execution failed")

        flow_config = {"name": "failing_flow"}

        # Execute
        secured_flow = self.adapter.create_secure_flow(
            failing_flow,
            flow_id="failing_flow",
            flow_config=flow_config,
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_flow()

        self.assertEqual(str(context.exception), "Flow execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "flow_execution_error",
            {"flow_id": "failing_flow", "error": "Flow execution failed"},
            "ERROR"
        )


if __name__ == '__main__':
    unittest.main()
