"""Tests for Semantic Kernel Adapter"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from zta_agent.integrations.semantic_kernel_adapter import SemanticKernelAdapter
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestSemanticKernelAdapter(unittest.TestCase):
    """Test cases for SemanticKernelAdapter"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_auth = Mock(spec=AuthenticationManager)
        self.mock_policy = Mock(spec=PolicyEngine)
        self.mock_monitor = Mock(spec=SecurityMonitor)

        self.adapter = SemanticKernelAdapter(
            self.mock_auth,
            self.mock_policy,
            self.mock_monitor
        )

    def test_validate_kernel_function_success(self):
        """Test successful kernel function validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        function_args = {"input": "test data"}

        # Execute
        result = self.adapter.validate_kernel_function(
            function_name="Summarize",
            function_args=function_args,
            plugin_name="TextPlugin",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_auth.validate_token.assert_called_once_with("valid_token")
        self.mock_policy.evaluate.assert_called_once()
        self.mock_monitor.record_event.assert_called()

    def test_validate_kernel_function_invalid_token(self):
        """Test kernel function with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_kernel_function(
            function_name="Summarize",
            function_args={},
            plugin_name="TextPlugin",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "unauthorized_kernel_function",
            {"function_name": "Summarize", "plugin_name": "TextPlugin"},
            "WARNING"
        )

    def test_validate_kernel_function_policy_denied(self):
        """Test kernel function when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_kernel_function(
            function_name="DeleteData",
            function_args={"target": "production"},
            plugin_name="AdminPlugin",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)
        self.mock_monitor.record_event.assert_called_with(
            "kernel_function_validation",
            {
                "function_name": "DeleteData",
                "plugin_name": "AdminPlugin",
                "agent_id": "test_user",
                "allowed": False
            },
            "WARNING"
        )

    def test_validate_plugin_access_success(self):
        """Test successful plugin access validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_plugin_access(
            plugin_name="TextPlugin",
            operation="execute",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_plugin_access_invalid_token(self):
        """Test plugin access with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_plugin_access(
            plugin_name="TextPlugin",
            operation="load",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_planner_execution_success(self):
        """Test successful planner execution validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        available_functions = ["Search", "Summarize", "Calculate"]

        # Execute
        result = self.adapter.validate_planner_execution(
            planner_name="BasicPlanner",
            goal="Research and summarize quantum computing",
            available_functions=available_functions,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_planner_execution_policy_denied(self):
        """Test planner execution when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        available_functions = ["DeleteData", "ModifySystem"]

        # Execute
        result = self.adapter.validate_planner_execution(
            planner_name="StepwisePlanner",
            goal="Administrative task",
            available_functions=available_functions,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_memory_access_success(self):
        """Test successful memory access validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        # Execute
        result = self.adapter.validate_memory_access(
            collection_name="user_preferences",
            operation="retrieve",
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_memory_access_invalid_token(self):
        """Test memory access with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        # Execute
        result = self.adapter.validate_memory_access(
            collection_name="sensitive_data",
            operation="save",
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_memory_access_delete_denied(self):
        """Test memory delete operation when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "regular_user"}
        self.mock_policy.evaluate.return_value = False

        # Execute
        result = self.adapter.validate_memory_access(
            collection_name="production_data",
            operation="delete",
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_prompt_render_success(self):
        """Test successful prompt render validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        prompt_template = "Summarize the following: {{$input}}"
        variables = {"input": "test content"}

        # Execute
        result = self.adapter.validate_prompt_render(
            prompt_template=prompt_template,
            variables=variables,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_prompt_render_policy_denied(self):
        """Test prompt render when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        prompt_template = "Execute system command: {{$command}}"
        variables = {"command": "rm -rf /"}

        # Execute
        result = self.adapter.validate_prompt_render(
            prompt_template=prompt_template,
            variables=variables,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_create_secure_kernel_function_success(self):
        """Test creating a secure kernel function wrapper"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def mock_function(input: str) -> str:
            return f"Processed: {input}"

        # Execute
        secured_func = self.adapter.create_secure_kernel_function(
            mock_function,
            function_name="ProcessText",
            plugin_name="TextPlugin",
            token="valid_token"
        )

        # Execute the secured function
        result = secured_func(input="test data")

        # Assert
        self.assertEqual(result, "Processed: test data")
        self.mock_monitor.record_event.assert_any_call(
            "kernel_function_success",
            {"function_name": "ProcessText", "plugin_name": "TextPlugin"},
            "INFO"
        )

    def test_create_secure_kernel_function_blocked(self):
        """Test secure kernel function blocks unauthorized execution"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = False

        def mock_function(input: str) -> str:
            return f"Processed: {input}"

        # Execute
        secured_func = self.adapter.create_secure_kernel_function(
            mock_function,
            function_name="AdminFunction",
            plugin_name="AdminPlugin",
            token="valid_token"
        )

        # Assert - should raise PermissionError
        with self.assertRaises(PermissionError) as context:
            secured_func(input="test")

        self.assertIn("AdminPlugin.AdminFunction", str(context.exception))

    def test_create_secure_kernel_function_handles_errors(self):
        """Test secure kernel function handles function errors"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        def failing_function(input: str) -> str:
            raise RuntimeError("Function execution failed")

        # Execute
        secured_func = self.adapter.create_secure_kernel_function(
            failing_function,
            function_name="ProcessText",
            plugin_name="TextPlugin",
            token="valid_token"
        )

        # Assert - should raise the original error
        with self.assertRaises(RuntimeError) as context:
            secured_func(input="test")

        self.assertEqual(str(context.exception), "Function execution failed")
        self.mock_monitor.record_event.assert_any_call(
            "kernel_function_error",
            {
                "function_name": "ProcessText",
                "plugin_name": "TextPlugin",
                "error": "Function execution failed"
            },
            "ERROR"
        )

    def test_validate_chat_completion_success(self):
        """Test successful chat completion validation"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "test_user"}
        self.mock_policy.evaluate.return_value = True

        chat_history = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ]
        settings = {"temperature": 0.7, "max_tokens": 100}

        # Execute
        result = self.adapter.validate_chat_completion(
            chat_history=chat_history,
            settings=settings,
            token="valid_token"
        )

        # Assert
        self.assertTrue(result)
        self.mock_policy.evaluate.assert_called_once()

    def test_validate_chat_completion_invalid_token(self):
        """Test chat completion with invalid token"""
        # Setup
        self.mock_auth.validate_token.return_value = None

        chat_history = [{"role": "user", "content": "Hello"}]
        settings = {}

        # Execute
        result = self.adapter.validate_chat_completion(
            chat_history=chat_history,
            settings=settings,
            token="invalid_token"
        )

        # Assert
        self.assertFalse(result)

    def test_validate_chat_completion_policy_denied(self):
        """Test chat completion when policy denies"""
        # Setup
        self.mock_auth.validate_token.return_value = {"sub": "unauthorized_user"}
        self.mock_policy.evaluate.return_value = False

        chat_history = [{"role": "user", "content": "sensitive request"}]
        settings = {"temperature": 0.9}

        # Execute
        result = self.adapter.validate_chat_completion(
            chat_history=chat_history,
            settings=settings,
            token="valid_token"
        )

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
