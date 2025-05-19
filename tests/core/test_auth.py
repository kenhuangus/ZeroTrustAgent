import unittest
from unittest.mock import patch, MagicMock, ANY
from datetime import datetime, timedelta
import jwt # PyJWT for encoding/decoding tokens for testing purposes

from zta_agent.core.auth import AuthenticationManager
from zta_agent.core.auth_providers.oauth import OAuthProvider # For spec mocking

# A default config for tests
DEFAULT_CONFIG = {
    "secret_key": "test_secret_key",
    "token_expiry": 3600,  # 1 hour
    "refresh_token_expiry": 86400 * 7,  # 7 days
    "max_failed_attempts": 5,
    "lockout_duration": 300,  # 5 minutes
    "password_policy": {
        "min_length": 8
    },
    "oauth": { # Dummy OAuth config for provider testing
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "authorize_url": "https://example.com/authorize",
        "token_url": "https://example.com/token",
        "userinfo_url": "https://example.com/userinfo",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile email"
    }
}

class TestAuthenticationManager(unittest.TestCase):

    @patch('zta_agent.core.auth.CredentialStore')
    @patch('zta_agent.core.auth.TokenStore')
    @patch('zta_agent.core.auth.PasswordPolicy')
    @patch('zta_agent.core.auth.SecurityLogger')
    def setUp(self, MockSecurityLogger, MockPasswordPolicy, MockTokenStore, MockCredentialStore):
        self.MockCredentialStore = MockCredentialStore
        self.MockTokenStore = MockTokenStore
        self.MockPasswordPolicy = MockPasswordPolicy
        self.MockSecurityLogger = MockSecurityLogger

        self.config = DEFAULT_CONFIG.copy()
        self.auth_manager = AuthenticationManager(self.config)

        # Assign mocked instances to the auth_manager instance
        # This ensures that the auth_manager uses our mocks
        self.auth_manager.credential_store = self.MockCredentialStore()
        self.auth_manager.token_store = self.MockTokenStore()
        self.auth_manager.password_policy = self.MockPasswordPolicy()
        self.auth_manager.security_logger = self.MockSecurityLogger()
        
        # Reset mocks for each test
        self.MockCredentialStore.reset_mock()
        self.MockTokenStore.reset_mock()
        self.MockPasswordPolicy.reset_mock()
        self.MockSecurityLogger.reset_mock()
        
        # Ensure the auth_manager uses the mocked providers if any are specified in config
        # For example, if "oauth" is in DEFAULT_CONFIG, it will try to create an OAuthProvider
        # We can mock these out if specific provider tests need more control,
        # or let them be created if their simple instantiation is fine.
        # For `test_authenticate_delegates_to_oauth_provider`, we replace it manually.


    # 1. Initialization Tests
    def test_initialization_default_config(self):
        self.assertEqual(self.auth_manager.secret_key, DEFAULT_CONFIG["secret_key"])
        self.assertEqual(self.auth_manager.token_expiry, DEFAULT_CONFIG["token_expiry"])
        self.assertIsNotNone(self.auth_manager.credential_store)
        self.assertIsNotNone(self.auth_manager.token_store)
        self.assertIsNotNone(self.auth_manager.password_policy)
        self.assertIsNotNone(self.auth_manager.security_logger)

    def test_initialization_custom_config(self):
        custom_config = {
            "secret_key": "custom_secret",
            "token_expiry": 1800,
            "password_policy": {"min_length": 10}
        }
        auth_manager = AuthenticationManager(custom_config)
        self.assertEqual(auth_manager.secret_key, "custom_secret")
        self.assertEqual(auth_manager.token_expiry, 1800)
        # Check if password policy was initialized with the custom sub-config
        # The PasswordPolicy mock itself is called in __init__ of AuthenticationManager
        # So, we check the args it was constructed with.
        self.MockPasswordPolicy.assert_any_call({"min_length": 10})


    # 2. Password-based Authentication
    def test_password_provider_validate_credentials_failure(self):
        """Test password provider's validate_credentials method (which is on AuthManager itself)"""
        credentials = {"provider": "password", "identity": None, "secret": None} # Missing identity and secret
        # This is called by the main authenticate method.
        # We are testing the case where the provider's validate_credentials (which is self.auth_manager.validate_credentials) fails.
        
        # Temporarily make the auth_manager's own validate_credentials return False for testing
        # This simulates the check within the main authenticate() flow.
        with patch.object(self.auth_manager, 'validate_credentials', return_value=(False, "Missing identity or password")) as mock_validate:
            result = self.auth_manager.authenticate(credentials)
            self.assertIsNone(result)
            mock_validate.assert_called_once_with(credentials)
            self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
                None, False, None, None, details={'error': 'Missing identity or password'}
            )
            
    def test_create_credentials_success(self):
        self.MockPasswordPolicy.return_value.validate_password.return_value = (True, "")
        self.auth_manager.credential_store.store_credentials.return_value = True # Use the instance's mock
        
        success, message = self.auth_manager.create_credentials("test_user", "password123")
        
        self.assertTrue(success)
        self.assertEqual(message, "")
        self.MockPasswordPolicy.return_value.validate_password.assert_called_once_with("password123")
        self.auth_manager.credential_store.store_credentials.assert_called_once_with("test_user", ANY) # Hashed password
        self.auth_manager.security_logger.log_security_event.assert_called_with(
            "credentials_created", {"identity": "test_user"}
        )

    def test_create_credentials_failure_policy(self):
        self.MockPasswordPolicy.return_value.validate_password.return_value = (False, "Password too short")
        
        success, message = self.auth_manager.create_credentials("test_user", "pass")
        
        self.assertFalse(success)
        self.assertEqual(message, "Password too short")
        self.auth_manager.credential_store.store_credentials.assert_not_called()

    def test_authenticate_password_success(self):
        # This tests _handle_password_authentication implicitly via the main authenticate
        hashed_password = self.auth_manager.hash_password("password123")
        self.MockCredentialStore.return_value.get_credentials.return_value = {"password_hash": hashed_password}
        self.MockCredentialStore.return_value.get_failed_attempts.return_value = 0
        self.auth_manager.is_account_locked = MagicMock(return_value=False) # Mock is_account_locked part

        credentials = {"provider": "password", "identity": "test_user", "secret": "password123"}
        result = self.auth_manager.authenticate(credentials)

        self.assertIsNotNone(result)
        self.assertIn("access_token", result)
        self.assertIn("refresh_token", result)
        self.assertEqual(result["token_type"], "bearer")
        self.assertEqual(result["expires_in"], DEFAULT_CONFIG["token_expiry"])
        self.assertEqual(result["identity"], "test_user")
        self.auth_manager.credential_store.reset_failed_attempts.assert_called_with("test_user")
        self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
            "test_user", True, None, None, details={'provider': 'password'}
        )
        # Check token store was called for both tokens
        self.assertEqual(self.auth_manager.token_store.store_token.call_count, 2)


    def test_authenticate_password_failure_wrong_password(self):
        self.MockCredentialStore.return_value.get_credentials.return_value = {"password_hash": self.auth_manager.hash_password("correct_password")}
        self.auth_manager.is_account_locked = MagicMock(return_value=False)

        credentials = {"provider": "password", "identity": "test_user", "secret": "wrong_password"}
        result = self.auth_manager.authenticate(credentials)

        self.assertIsNone(result)
        self.auth_manager.credential_store.record_failed_attempt.assert_called_with("test_user")
        self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
            "test_user", False, None, None, details={'provider': 'password'}
        )

    def test_change_password_success(self):
        old_hashed_password = self.auth_manager.hash_password("old_password")
        self.MockCredentialStore.return_value.get_credentials.return_value = {
            "password_hash": old_hashed_password,
            "password_history": []
        }
        self.MockPasswordPolicy.return_value.validate_password.return_value = (True, "")
        self.MockCredentialStore.return_value.update_password.return_value = True

        success, message = self.auth_manager.change_password("test_user", "old_password", "new_password")

        self.assertTrue(success)
        self.assertEqual(message, "")
        self.auth_manager.password_policy.validate_password.assert_called_with("new_password", [])
        self.auth_manager.credential_store.update_password.assert_called_with("test_user", ANY, old_hashed_password)
        self.auth_manager.token_store.revoke_all_user_tokens.assert_called_with("test_user", "refresh")
        self.auth_manager.security_logger.log_password_change.assert_called_with("test_user", True)

    def test_change_password_failure_wrong_old_password(self):
        self.MockCredentialStore.return_value.get_credentials.return_value = {"password_hash": self.auth_manager.hash_password("correct_old_password")}
        
        success, message = self.auth_manager.change_password("test_user", "wrong_old_password", "new_password")

        self.assertFalse(success)
        self.assertEqual(message, "Invalid current password")
        self.auth_manager.credential_store.update_password.assert_not_called()

    # 3. Token Management
    def test_validate_token_success(self):
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(seconds=DEFAULT_CONFIG["token_expiry"])
        token_jti = "test_jti"
        
        token_payload = {
            "sub": "test_user",
            "iat": issued_at,
            "exp": expires_at,
            "jti": token_jti,
            "type": "access",
            "custom_claim": "value"
        }
        # Generate token using the auth_manager's method to ensure consistency
        # but for this test, we construct one to validate its decoding
        token = jwt.encode(token_payload, DEFAULT_CONFIG["secret_key"], algorithm="HS256")
        
        self.MockTokenStore.return_value.is_token_valid.return_value = True
        
        claims = self.auth_manager.validate_token(token)
        self.assertIsNotNone(claims)
        self.assertEqual(claims["sub"], "test_user")
        self.assertEqual(claims["jti"], token_jti)
        self.assertEqual(claims["type"], "access")
        self.assertEqual(claims["custom_claim"], "value")
        # PyJWT decodes 'iat' and 'exp' to timestamps
        self.assertAlmostEqual(claims["iat"], issued_at.timestamp(), places=0)
        self.assertAlmostEqual(claims["exp"], expires_at.timestamp(), places=0)
        self.auth_manager.token_store.is_token_valid.assert_called_with(token_jti)


    def test_generate_token_claims(self):
        identity = "token_user"
        token_type = "access"
        custom_claims = {"role": "admin", "provider": "password"}
        
        # Mock datetime to control iat and exp
        now = datetime.utcnow()
        with patch('zta_agent.core.auth.datetime') as mock_dt:
            mock_dt.utcnow.return_value = now
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs) # for timedelta
            
            token = self.auth_manager.generate_token(identity, token_type, custom_claims)
        
        self.assertIsNotNone(token)
        decoded_payload = jwt.decode(token, DEFAULT_CONFIG["secret_key"], algorithms=["HS256"])
        
        self.assertEqual(decoded_payload["sub"], identity)
        self.assertEqual(decoded_payload["type"], token_type)
        self.assertEqual(decoded_payload["role"], custom_claims["role"])
        self.assertEqual(decoded_payload["provider"], custom_claims["provider"])
        self.assertIn("jti", decoded_payload)
        self.assertAlmostEqual(decoded_payload["iat"], now.timestamp(), places=0)
        expected_exp = now + timedelta(seconds=DEFAULT_CONFIG["token_expiry"])
        self.assertAlmostEqual(decoded_payload["exp"], expected_exp.timestamp(), places=0)
        
        self.auth_manager.token_store.store_token.assert_called_once()
        self.auth_manager.security_logger.log_token_event.assert_called_once()


    def test_validate_token_failure_invalid_signature(self):
        token = jwt.encode({"sub": "test_user"}, "wrong_key", algorithm="HS256")
        claims = self.auth_manager.validate_token(token)
        self.assertIsNone(claims)

    @patch('zta_agent.core.auth.datetime')
    def test_validate_token_failure_expired(self, mock_datetime):
        past_time = datetime.utcnow() - timedelta(seconds=7200) # 2 hours ago
        mock_datetime.utcnow.return_value = past_time # Token issued in the "past"
        
        token_claims = {
            "sub": "test_user",
            "iat": past_time, # issued at this "past" time
            "exp": past_time + timedelta(seconds=3600), # expired 1 hour ago from "now"
            "jti": "expired_jti",
            "type": "access"
        }
        token = jwt.encode(token_claims, DEFAULT_CONFIG["secret_key"], algorithm="HS256")

        # Now advance "utcnow" to present time for validation check
        mock_datetime.utcnow.return_value = datetime.utcnow() # Real current time for validation
        
        self.MockTokenStore.return_value.is_token_valid.return_value = True 
        claims = self.auth_manager.validate_token(token)
        self.assertIsNone(claims) # Should be None because exp < datetime.utcnow().timestamp()

    def test_refresh_access_token_success(self):
        refresh_token_jti = "refresh_jti"
        refresh_token_claims = {
            "sub": "test_user",
            "exp": datetime.utcnow() + timedelta(days=1),
            "jti": refresh_token_jti,
            "type": "refresh"
        }
        refresh_token = jwt.encode(refresh_token_claims, DEFAULT_CONFIG["secret_key"], algorithm="HS256")
        
        self.MockTokenStore.return_value.is_token_valid.return_value = True # Refresh token itself is valid

        result = self.auth_manager.refresh_access_token(refresh_token)
        self.assertIsNotNone(result)
        self.assertIn("access_token", result)
        self.assertEqual(result["token_type"], "bearer")
        self.assertEqual(result["expires_in"], DEFAULT_CONFIG["token_expiry"])
        
        # Verify new access token stored
        self.auth_manager.token_store.store_token.assert_called_with(
            jti=ANY, token_type="access", identity="test_user", expires_at=ANY
        )
        self.auth_manager.security_logger.log_token_event.assert_any_call(
            "issued", ANY, "test_user", {"type": "access", "provider": "refresh", "identity": "test_user"} # Claims from generate_token
        )

    def test_refresh_access_token_failure_invalid_refresh_token(self):
        invalid_refresh_token = "this.is.not.a.valid.jwt"
        # Test case 1: Completely invalid token string
        result = self.auth_manager.refresh_access_token(invalid_refresh_token)
        self.assertIsNone(result)

        # Test case 2: Valid JWT but not a refresh token (e.g. wrong type)
        access_token_claims = {
            "sub": "test_user",
            "exp": datetime.utcnow() + timedelta(days=1),
            "jti": "not_a_refresh_jti",
            "type": "access" # Crucially, this is 'access', not 'refresh'
        }
        not_a_refresh_token = jwt.encode(access_token_claims, DEFAULT_CONFIG["secret_key"], algorithm="HS256")
        self.MockTokenStore.return_value.is_token_valid.return_value = True # Assume JTI is valid for this test
        
        result_wrong_type = self.auth_manager.refresh_access_token(not_a_refresh_token)
        self.assertIsNone(result_wrong_type)
        self.auth_manager.token_store.is_token_valid.assert_called_with("not_a_refresh_jti")


    def test_revoke_token_success(self):
        token_jti = "revoke_jti"
        token = jwt.encode({
            "sub": "test_user", 
            "exp": datetime.utcnow() + timedelta(seconds=3600),
            "jti": token_jti,
            "type": "access"
            }, DEFAULT_CONFIG["secret_key"], algorithm="HS256")
            
        self.MockTokenStore.return_value.revoke_token.return_value = True
        
        success = self.auth_manager.revoke_token(token)
        self.assertTrue(success)
        self.auth_manager.token_store.revoke_token.assert_called_with(token_jti)
        self.auth_manager.security_logger.log_token_event.assert_called_with(
            "revoked", token_jti, "test_user"
        )

    def test_validate_token_after_revocation(self):
        token_jti = "revoked_jti"
        token = jwt.encode({
            "sub": "test_user",
            "exp": datetime.utcnow() + timedelta(seconds=3600),
            "jti": token_jti,
            "type": "access"
        }, DEFAULT_CONFIG["secret_key"], algorithm="HS256")

        # First, validate (it's valid before revocation)
        self.MockTokenStore.return_value.is_token_valid.return_value = True
        claims = self.auth_manager.validate_token(token)
        self.assertIsNotNone(claims)

        # Now, revoke
        self.MockTokenStore.return_value.revoke_token.return_value = True
        self.auth_manager.revoke_token(token)

        # Now, is_token_valid should return False for this jti
        self.MockTokenStore.return_value.is_token_valid.return_value = False
        claims_after_revoke = self.auth_manager.validate_token(token)
        self.assertIsNone(claims_after_revoke)
        
        # Ensure is_token_valid was checked for the specific JTI
        self.auth_manager.token_store.is_token_valid.assert_called_with(token_jti)


    def test_revoke_all_user_tokens_success(self):
        self.MockTokenStore.return_value.revoke_all_user_tokens.return_value = True
        success = self.auth_manager.revoke_all_user_tokens("test_user")
        self.assertTrue(success)
        self.auth_manager.token_store.revoke_all_user_tokens.assert_called_with("test_user")
        self.auth_manager.security_logger.log_security_event.assert_called_with(
            "all_tokens_revoked", {"identity": "test_user"}
        )

    # 4. Account Lockout
    @patch('zta_agent.core.auth.AuthenticationManager._verify_password_credentials') # Mock verification
    def test_authenticate_password_account_locked(self, mock_verify_creds):
        # This tests _handle_password_authentication implicitly
        mock_verify_creds.return_value = True # Assume password would be correct
        self.auth_manager.is_account_locked = MagicMock(return_value=True)
        
        credentials = {"provider": "password", "identity": "test_user", "secret": "password123"}
        result = self.auth_manager.authenticate(credentials)
        
        self.assertIsNone(result)
        self.auth_manager.is_account_locked.assert_called_with("test_user")
        self.auth_manager.credential_store.record_failed_attempt.assert_not_called() # Not called if already locked
        self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
            "test_user", False, None, None, details={'error': 'Account locked', 'provider': 'password'}
        )


    def test_record_failed_attempt_call(self):
        # This tests _handle_password_authentication implicitly
        self.MockCredentialStore.return_value.get_credentials.return_value = None # User not found
        self.auth_manager.is_account_locked = MagicMock(return_value=False)

        credentials = {"provider": "password", "identity": "test_user", "secret": "wrong_password"}
        self.auth_manager.authenticate(credentials)
        self.auth_manager.credential_store.record_failed_attempt.assert_called_with("test_user")

    @patch('zta_agent.core.auth.datetime')
    def test_is_account_locked_logic_locked(self, mock_datetime):
        self.MockCredentialStore.return_value.get_failed_attempts.return_value = DEFAULT_CONFIG["max_failed_attempts"]
        # Last attempt was recent, within lockout_duration
        self.MockCredentialStore.return_value.get_last_attempt.return_value = datetime.utcnow() - timedelta(seconds=100)
        mock_datetime.utcnow.return_value = datetime.utcnow()

        self.assertTrue(self.auth_manager.is_account_locked("test_user"))

    @patch('zta_agent.core.auth.datetime')
    def test_is_account_locked_logic_lock_expired(self, mock_datetime):
        self.MockCredentialStore.return_value.get_failed_attempts.return_value = DEFAULT_CONFIG["max_failed_attempts"]
        # Last attempt was long ago, outside lockout_duration
        self.MockCredentialStore.return_value.get_last_attempt.return_value = datetime.utcnow() - timedelta(seconds=DEFAULT_CONFIG["lockout_duration"] + 60)
        mock_datetime.utcnow.return_value = datetime.utcnow()
        
        self.assertFalse(self.auth_manager.is_account_locked("test_user"))

    def test_is_account_locked_logic_not_enough_attempts(self):
        self.MockCredentialStore.return_value.get_failed_attempts.return_value = DEFAULT_CONFIG["max_failed_attempts"] - 1
        self.assertFalse(self.auth_manager.is_account_locked("test_user"))

    # 5. Authentication Providers (Mocking)
    def test_authenticate_delegates_to_oauth_provider(self):
        # Re-initialize auth_manager with a mock OAuth provider for this test
        # This is because setUp uses the actual class if "oauth" is in config
        
        mock_oauth_provider = MagicMock(spec=OAuthProvider)
        self.auth_manager.auth_providers["oauth"] = mock_oauth_provider
        
        oauth_credentials = {
            "provider": "oauth", 
            "code": "auth_code_123", 
            "ip_address": "1.2.3.4"
        }
        
        # Mock provider methods
        mock_oauth_provider.validate_credentials.return_value = (True, "")
        mock_oauth_provider.authenticate.return_value = {
            "identity": "oauth_user", 
            "email": "oauth@example.com",
            "provider_specific_data": "some_data"
        }

        result = self.auth_manager.authenticate(oauth_credentials)

        self.assertIsNotNone(result)
        mock_oauth_provider.validate_credentials.assert_called_once_with(oauth_credentials)
        mock_oauth_provider.authenticate.assert_called_once_with(oauth_credentials)
        
        self.assertIn("access_token", result)
        self.assertIn("refresh_token", result)
        self.assertEqual(result["identity"], "oauth_user")
        self.assertEqual(result["email"], "oauth@example.com")

        self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
            "oauth_user", True, "1.2.3.4", None, details={'provider': 'oauth'}
        )
        # Check token store was called for both tokens
        self.assertEqual(self.auth_manager.token_store.store_token.call_count, 2)


    def test_authenticate_unknown_provider(self):
        credentials = {"provider": "unknown_provider", "identity": "test_user"}
        result = self.auth_manager.authenticate(credentials)
        self.assertIsNone(result)
        self.auth_manager.security_logger.log_authentication_attempt.assert_called_with(
            "test_user", False, None, None, details={'error': 'Unknown provider: unknown_provider'}
        )

    # 6. Security Logging (Mocking examples, more are tested implicitly above)
    def test_security_logging_on_token_issued(self):
        # This is somewhat tested in test_authenticate_password_success and token refresh
        # Here's a more direct test of generate_token's logging
        self.auth_manager.generate_token("log_user", "access", {"custom_claim": "value"})
        self.auth_manager.security_logger.log_token_event.assert_called_with(
            "issued", ANY, "log_user", {"type": "access", "custom_claim": "value"}
        )

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

# Example of how to run this if you are in the project root:
# python -m unittest tests.core.test_auth
