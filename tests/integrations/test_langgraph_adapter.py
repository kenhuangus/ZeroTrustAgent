"""Tests for LangGraph Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.langgraph_adapter import LangGraphAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestLangGraphAdapter(unittest.TestCase):
    """Test cases for LangGraphAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = LangGraphAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_node_execution_success(self):
        """Test successful node execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        state = {"messages": [], "current_step": 1}

        # Execute
        result = self.adapter.validate_node_execution(
            node_id="process_node",
            state=state,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_node_execution_invalid_token(self):
        """Test node execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        state = {"messages": []}

        # Execute
        result = self.adapter.validate_node_execution(
            node_id="process_node",
            state=state,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_node_execution",
            {"node_id": "process_node", "state_keys": ["messages"]},
            "WARNING"
        )

    def test_validate_node_execution_policy_denied(self):
        """Test node execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = False

        state = {"messages": []}

        # Execute
        result = self.adapter.validate_node_execution(
            node_id="restricted_node",
            state=state,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "node_execution_validation",
            {
                "node_id": "restricted_node",
                "agent_id": "test_agent",
                "allowed": False
            },
            "WARNING"
        )

    def test_validate_state_transition_success(self):
        """Test successful state transition validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        state = {"step": 1}

        # Execute
        result = self.adapter.validate_state_transition(
            from_node="node_a",
            to_node="node_b",
            state=state,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_state_transition_invalid_token(self):
        """Test state transition with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        state = {"step": 1}

        # Execute
        result = self.adapter.validate_state_transition(
            from_node="node_a",
            to_node="node_b",
            state=state,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_tool_call_success(self):
        """Test successful tool call validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        tool_args = {"query": "test search"}

        # Execute
        result = self.adapter.validate_tool_call(
            tool_name="search_tool",
            tool_args=tool_args,
            node_id="research_node",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_tool_call_policy_denied(self):
        """Test tool call when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = False

        tool_args = {"command": "rm -rf /"}

        # Execute
        result = self.adapter.validate_tool_call(
            tool_name="dangerous_tool",
            tool_args=tool_args,
            node_id="any_node",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_node_success(self):
        """Test creating a secure node wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        def sample_node(state):
            return {"result": "processed"}

        # Execute
        secured_node = self.adapter.create_secure_node(
            sample_node,
            node_id="test_node",
            token="valid_token"
        )

        # Execute the secured node
        result = secured_node({"input": "data"})

        # Assert
        self.assertEqual(result, {"result": "processed"})
        self.mock_monitor.record_event.assert_any_call(
            "node_execution_success",
            {"node_id": "test_node"},
            "INFO"
        )

    def test_create_secure_node_blocked(self):
        """Test secure node wrapper blocks unauthorized execution"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = False

        def sample_node(state):
            return {"result": "processed"}

        # Execute
        secured_node = self.adapter.create_secure_node(
            sample_node,
            node_id="restricted_node",
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_node({"input": "data"})

        self.assertIn("restricted_node", str(context.exception))

    def test_create_secure_node_handles_errors(self):
        """Test secure node wrapper handles node function errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        def failing_node(state):
            raise ValueError("Node execution failed")

        # Execute
        secured_node = self.adapter.create_secure_node(
            failing_node,
            node_id="failing_node",
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(ValueError) as context:
            secured_node({"input": "data"})

        self.assertEqual(str(context.exception), "Node execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "node_execution_error",
            {"node_id": "failing_node", "error": "Node execution failed"},
            "ERROR"
        )

    def test_validate_agent_communication_success(self):
        """Test successful agent communication validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "agent_a"}
        self.mock_policy.evaluate.return_value = True

        message = {"type": "request", "content": "Hello"}

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="agent_a",
            target_agent="agent_b",
            message=message,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)

    def test_validate_agent_communication_denied(self):
        """Test agent communication when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_agent"}
        self.mock_policy.evaluate.return_value = False

        message = {"type": "request"}

        # Execute
        result = self.adapter.validate_agent_communication(
            source_agent="unauthorized_agent",
            target_agent="agent_b",
            message=message,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_secure_graph_execution_success(self):
        """Test successful graph execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = True

        graph_config = {
            "nodes": ["start", "process", "end"],
            "edges": [["start", "process"], ["process", "end"]]
        }
        initial_state = {"input": "data"}

        # Execute
        result = self.adapter.secure_graph_execution(
            graph_config=graph_config,
            initial_state=initial_state,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result["allowed"])
        self.assertEqual(result["agent_id"], "test_agent")
        self.assertEqual(result["graph_config"], graph_config)

    def test_secure_graph_execution_invalid_token(self):
        """Test graph execution with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        graph_config = {"nodes": ["start"], "edges": []}
        initial_state = {}

        # Execute
        result = self.adapter.secure_graph_execution(
            graph_config=graph_config,
            initial_state=initial_state,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result["allowed"])
        self.assertEqual(result["error"], "Invalid authentication token")
        self.assertIsNone(result.get("graph_config"))

    def test_secure_graph_execution_policy_denied(self):
        """Test graph execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_agent"}
        self.mock_policy.evaluate.return_value = False

        graph_config = {
            "nodes": ["restricted_node"],
            "edges": []
        }
        initial_state = {}

        # Execute
        result = self.adapter.secure_graph_execution(
            graph_config=graph_config,
            initial_state=initial_state,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result["allowed"])
        self.assertIsNone(result.get("graph_config"))


if __name__ == '__main__':
    unittest.main()
