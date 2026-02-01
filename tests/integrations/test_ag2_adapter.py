"""Tests for AG2 (AutoGen v2) Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.ag2_adapter import AG2Adapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestAG2Adapter(unittest.TestCase):
    """Test cases for AG2Adapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = AG2Adapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_agent_registration_success(self):
        """Test successful agent registration validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        agent_config = {
            "type": "assistant",
            "capabilities": ["chat", "code"],
            "can_execute_code": False
        }

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="assistant_1",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_agent_registration_invalid_token(self):
        """Test agent registration with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        agent_config = {"type": "assistant"}

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="assistant_1",
            agent_config=agent_config,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_agent_registration",
            {"agent_id": "assistant_1", "agent_type": "assistant"},
            "WARNING"
        )

    def test_validate_agent_registration_policy_denied(self):
        """Test agent registration when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        agent_config = {
            "type": "code_executor",
            "can_execute_code": True
        }

        # Execute
        result = self.adapter.validate_agent_registration(
            agent_id="code_agent",
            agent_config=agent_config,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_message_routing_success(self):
        """Test successful message routing validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        message = {
            "type": "text",
            "content": "Hello, how are you?"
        }

        # Execute
        result = self.adapter.validate_message_routing(
            sender_id="agent_a",
            recipient_id="agent_b",
            message=message,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_message_routing_invalid_token(self):
        """Test message routing with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        message = {"type": "text", "content": "Hello"}

        # Execute
        result = self.adapter.validate_message_routing(
            sender_id="agent_a",
            recipient_id="agent_b",
            message=message,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_code_execution_success(self):
        """Test successful code execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        code = "print('Hello World')"

        # Execute
        result = self.adapter.validate_code_execution(
            agent_id="code_agent",
            code=code,
            language="python",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_code_execution_dangerous_patterns(self):
        """Test code execution with dangerous patterns"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        code = "os.system('rm -rf /')"

        # Execute
        result = self.adapter.validate_code_execution(
            agent_id="code_agent",
            code=code,
            language="python",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)
        # Check that has_dangerous_patterns is in context
        call_args = self.mock_policy.evaluate.call_args[0][0]
        self.assertTrue(call_args.get("has_dangerous_patterns"))

    def test_validate_code_execution_invalid_token(self):
        """Test code execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_code_execution(
            agent_id="code_agent",
            code="print('test')",
            language="python",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_group_chat_operation_success(self):
        """Test successful group chat operation validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        agent_ids = ["agent_a", "agent_b", "agent_c"]

        # Execute
        result = self.adapter.validate_group_chat_operation(
            operation="create",
            group_id="group_1",
            agent_ids=agent_ids,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_group_chat_operation_invalid_token(self):
        """Test group chat operation with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_group_chat_operation(
            operation="create",
            group_id="group_1",
            agent_ids=["agent_a"],
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_group_chat_operation_policy_denied(self):
        """Test group chat operation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_group_chat_operation(
            operation="delete",
            group_id="production_group",
            agent_ids=["agent_a", "agent_b"],
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
            agent_id="agent_1",
            tool_name="search_tool",
            tool_args=tool_args,
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
            agent_id="agent_1",
            tool_name="search_tool",
            tool_args={},
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_usage_policy_denied(self):
        """Test tool usage when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_tool_usage(
            agent_id="agent_1",
            tool_name="dangerous_tool",
            tool_args={"command": "delete_all"},
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
            return "Agent executed"

        agent_config = {"type": "assistant"}

        # Execute
        secured_agent = self.adapter.create_secure_agent(
            mock_agent,
            agent_id="assistant_1",
            agent_config=agent_config,
            token="valid_token"
        )

        # Execute the secured agent
        result = secured_agent()

        # Assert
        self.assertEqual(result, "Agent executed")
        self.mock_monitor.record_event.assert_any_call(
            "agent_execution_success",
            {"agent_id": "assistant_1"},
            "INFO"
        )

    def test_create_secure_agent_blocked(self):
        """Test secure agent wrapper blocks unauthorized registration"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_agent():
            return "Agent executed"

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

    def test_validate_llm_call_success(self):
        """Test successful LLM call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi!"}
        ]

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4",
            messages=messages,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_llm_call_invalid_token(self):
        """Test LLM call with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        messages = [{"role": "user", "content": "Hello"}]

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4",
            messages=messages,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_llm_call_policy_denied(self):
        """Test LLM call when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        messages = [{"role": "user", "content": "sensitive request"}]

        # Execute
        result = self.adapter.validate_llm_call(
            agent_id="agent_1",
            model="gpt-4",
            messages=messages,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
