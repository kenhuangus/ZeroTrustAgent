"""Integration tests for Zero Trust Agent"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import yaml

from zta_agent import initialize_agent
from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.policy import PolicyEngine
from zta_agent.core.monitor import SecurityMonitor


class TestZeroTrustAgentIntegration(unittest.TestCase):
    """Integration tests for the complete ZTA system"""

    def setUp(self):
        """Set up test environment with temporary config"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_policy.yaml")

        # Create test configuration
        config = {
            "auth": {
                "secret_key": "test_secret_key",
                "token_expiry": 3600,
                "refresh_token_expiry": 86400,
                "max_failed_attempts": 5,
                "lockout_duration": 300,
                "password_policy": {
                    "min_length": 8
                }
            },
            "policies": {
                "policies": [
                    {
                        "name": "allow_research_agents",
                        "conditions": {
                            "agent_id": {"regex": "^research_.*"},
                            "action_type": {"in": ["execute_task", "research"]}
                        },
                        "effect": "allow",
                        "priority": 90
                    },
                    {
                        "name": "deny_all",
                        "conditions": {},
                        "effect": "deny",
                        "priority": 0
                    }
                ]
            }
        }

        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)

    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('zta_agent.core.auth.CredentialStore')
    @patch('zta_agent.core.auth.TokenStore')
    def test_full_authentication_flow(self, mock_token_store, mock_credential_store):
        """Test complete authentication flow"""
        # Setup mocks
        mock_credential_store.return_value.get_credentials.return_value = {
            "password_hash": AuthenticationManager("").hash_password("test_password")
        }
        mock_credential_store.return_value.get_failed_attempts.return_value = 0
        mock_token_store.return_value.is_token_valid.return_value = True

        # Initialize agent
        components = initialize_agent(self.config_path)
        auth_manager = components['auth_manager']

        # Create credentials
        success, error = auth_manager.create_credentials("test_user", "SecurePass123!")
        self.assertTrue(success)

        # Authenticate
        result = auth_manager.authenticate({
            "identity": "test_user",
            "secret": "SecurePass123!",
            "ip_address": "127.0.0.1",
            "user_agent": "Test/1.0"
        })

        self.assertIsNotNone(result)
        self.assertIn("access_token", result)
        self.assertIn("refresh_token", result)
        self.assertEqual(result["identity"], "test_user")

    def test_policy_enforcement_flow(self):
        """Test policy enforcement with different agents"""
        components = initialize_agent(self.config_path)
        policy_engine = components['policy_engine']

        # Test allowed agent
        allowed_context = {
            "agent_id": "research_agent_1",
            "action_type": "execute_task"
        }
        self.assertTrue(policy_engine.evaluate(allowed_context))

        # Test denied agent
        denied_context = {
            "agent_id": "malicious_agent",
            "action_type": "execute_task"
        }
        self.assertFalse(policy_engine.evaluate(denied_context))

    @patch('zta_agent.core.auth.CredentialStore')
    @patch('zta_agent.core.auth.TokenStore')
    def test_crewai_adapter_integration(self, mock_token_store, mock_credential_store):
        """Test CrewAI adapter integration"""
        # Setup mocks
        mock_credential_store.return_value.get_credentials.return_value = {
            "password_hash": AuthenticationManager("").hash_password("test_password")
        }
        mock_credential_store.return_value.get_failed_attempts.return_value = 0
        mock_token_store.return_value.is_token_valid.return_value = True

        components = initialize_agent(self.config_path)
        crewai_adapter = components['crewai_adapter']
        auth_manager = components['auth_manager']

        # Create and authenticate agent
        auth_manager.create_credentials("research_agent_1", "test_password")
        auth_result = auth_manager.authenticate({
            "identity": "research_agent_1",
            "secret": "test_password"
        })
        token = auth_result["access_token"]

        # Test action validation
        result = crewai_adapter.validate_agent_action(
            agent_id="research_agent_1",
            action={"type": "execute_task", "resource": "operation"},
            token=token
        )
        self.assertTrue(result)

    def test_security_monitor_integration(self):
        """Test security monitor records events"""
        components = initialize_agent(self.config_path)
        security_monitor = components['security_monitor']

        # Record test event
        security_monitor.record_event(
            "test_event",
            {"test": "data"},
            "INFO"
        )

        # Get events
        events = security_monitor.get_events()
        self.assertGreater(len(events), 0)


class TestEndToEndScenarios(unittest.TestCase):
    """End-to-end test scenarios"""

    def test_multi_agent_collaboration_security(self):
        """Test security in multi-agent collaboration"""
        # This would test a complete scenario with multiple agents
        # collaborating while being monitored by ZTA
        pass

    def test_token_refresh_flow(self):
        """Test complete token refresh flow"""
        pass

    def test_account_lockout_scenario(self):
        """Test account lockout after failed attempts"""
        pass


if __name__ == '__main__':
    unittest.main()
