"""
Authentication Manager for Zero Trust Security Agent
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import secrets
import bcrypt
import base64
from .credential_store import CredentialStore
from .token_store import TokenStore
from .password_policy import PasswordPolicy
from .security_logger import SecurityLogger
from .auth_providers.base import AuthenticationProvider
from .auth_providers.oauth import OAuthProvider
from .auth_providers.certificate import CertificateProvider
from .auth_providers.social.google import GoogleOAuthProvider
from .auth_providers.social.github import GitHubOAuthProvider
from .auth_providers.social.entra import EntraIDOAuthProvider

class AuthenticationManager:
    def __init__(self, config: Dict) -> None:
        self.secret_key = config.get("secret_key", secrets.token_hex(32))
        self.token_expiry = config.get("token_expiry", 3600)  # 1 hour default
        self.refresh_token_expiry = config.get("refresh_token_expiry", 86400 * 7)  # 7 days
        self.max_failed_attempts = config.get("max_failed_attempts", 5)
        self.lockout_duration = config.get("lockout_duration", 300)  # 5 minutes
        
        # Initialize components
        self.credential_store = CredentialStore()
        self.token_store = TokenStore()
        self.password_policy = PasswordPolicy(config.get("password_policy", {}))
        self.security_logger = SecurityLogger(config)

        # Initialize authentication providers
        self.auth_providers: Dict[str, AuthenticationProvider] = {}
        self._setup_auth_providers(config)

    def _setup_auth_providers(self, config: Dict) -> None:
        """
        Initializes and configures authentication providers based on the provided configuration.

        This method dynamically sets up providers like Google, GitHub, EntraID,
        generic OAuth, and certificate-based authentication if they are specified
        in the configuration dictionary. Password-based authentication is always
        enabled by default.

        Args:
            config: A dictionary containing the configuration for various
                    authentication providers. Keys typically include "google",
                    "github", "entra", "oauth", "certificate".
        """
        # Setup social OAuth providers
        if "google" in config:
            self.auth_providers["google"] = GoogleOAuthProvider(config["google"])

        if "github" in config:
            self.auth_providers["github"] = GitHubOAuthProvider(config["github"])

        if "entra" in config:
            self.auth_providers["entra"] = EntraIDOAuthProvider(config["entra"])

        # Setup generic OAuth provider if configured
        if "oauth" in config:
            self.auth_providers["oauth"] = OAuthProvider(config["oauth"])

        # Setup certificate provider if configured
        if "certificate" in config:
            self.auth_providers["certificate"] = CertificateProvider(config["certificate"])

        # Password-based auth is always available
        # The AuthenticationManager itself handles password authentication flows
        # via _handle_password_authentication and validates credentials via validate_credentials.
        self.auth_providers["password"] = self

    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticates a user or entity based on the provided credentials and provider.

        This method acts as the main entry point for authentication. It identifies the
        specified authentication provider (defaulting to "password"), validates the
        credentials format with the provider, and then attempts authentication.
        If successful, it generates access and refresh JWT tokens.

        Args:
            credentials: A dictionary containing authentication information.
                         Expected keys:
                         - "provider" (str, optional): The name of the authentication
                           provider to use (e.g., "password", "google", "oauth").
                           Defaults to "password".
                         - "identity" (str): The user's identifier (e.g., username).
                         - "secret" (str, for password provider): The user's password.
                         - "ip_address" (str, optional): The IP address of the client.
                         - "user_agent" (str, optional): The user agent string of the client.
                         - Other provider-specific keys (e.g., "code" for OAuth).

        Returns:
            Optional[Dict]: A dictionary containing the authentication tokens and user
                            information if authentication is successful. Includes:
                            - "access_token" (str): The JWT access token.
                            - "refresh_token" (str): The JWT refresh token.
                            - "token_type" (str): Typically "bearer".
                            - "expires_in" (int): The lifetime of the access token in seconds.
                            - Additional provider-specific data from `auth_result`.
                            Returns None if authentication fails or the provider is unknown.
        """
        provider_name = credentials.get("provider", "password")
        provider = self.auth_providers.get(provider_name)
        
        if not provider:
            self.security_logger.log_authentication_attempt(
                credentials.get("identity", "unknown"),
                False,
                credentials.get("ip_address"),
                credentials.get("user_agent"),
                details={"error": f"Unknown provider: {provider_name}"}
            )
            return None

        # Validate credentials format
        is_valid, error = provider.validate_credentials(credentials)
        if not is_valid:
            self.security_logger.log_authentication_attempt(
                credentials.get("identity", "unknown"),
                False,
                credentials.get("ip_address"),
                credentials.get("user_agent"),
                details={"error": error}
            )
            return None

        # Authenticate with provider
        if provider_name == "password":
            auth_result = self._handle_password_authentication(credentials)
        else:
            auth_result = provider.authenticate(credentials)
        
        if auth_result:
            # Generate tokens
            # Note: For password auth, auth_result already contains token info
            # from _handle_password_authentication. For others, it's just identity info.
            identity = auth_result.get("identity")
            if not identity: # Should always be present from providers or _handle_password_auth
                self.security_logger.log_authentication_attempt(
                    credentials.get("identity", "unknown"),
                    False,
                    credentials.get("ip_address"),
                    credentials.get("user_agent"),
                    details={"error": "Authentication result missing identity", "provider": provider_name}
                )
                return None

            # If tokens are already generated by the handler (e.g. password specific one)
            # we can use them directly. Otherwise, generate new ones.
            if "access_token" in auth_result and "refresh_token" in auth_result:
                final_auth_result = auth_result
            else:
                access_token = self.generate_token(
                    identity,
                    "access",
                    {"provider": provider_name, **auth_result}
                )
                refresh_token = self.generate_token(
                    identity,
                    "refresh",
                    {"provider": provider_name} # Refresh token typically doesn't carry full claims
                )
                final_auth_result = {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": self.token_expiry,
                    **auth_result # Add original auth_result fields like identity, email etc.
                }

            self.security_logger.log_authentication_attempt(
                identity,
                True,
                credentials.get("ip_address"),
                credentials.get("user_agent"),
                details={"provider": provider_name}
            )

            return final_auth_result

        self.security_logger.log_authentication_attempt(
            credentials.get("identity", "unknown"),
            False,
            credentials.get("ip_address"),
            credentials.get("user_agent"),
            details={"provider": provider_name}
        )
        return None

    def generate_token(self, identity: str, token_type: str = "access",
                      claims: Optional[Dict] = None) -> str:
        """Generate a JWT token for the given identity."""
        if claims is None:
            claims = {}

        expiry = self.refresh_token_expiry if token_type == "refresh" else self.token_expiry
        jti = secrets.token_hex(16)
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(seconds=expiry)

        payload = {
            "sub": identity,
            "iat": issued_at,
            "exp": expires_at,
            "jti": jti,
            "type": token_type,
            **claims
        }

        # Store token in database
        self.token_store.store_token(
            jti=jti,
            token_type=token_type,
            identity=identity,
            expires_at=expires_at
        )

        self.security_logger.log_token_event(
            "issued",
            jti,
            identity,
            {"type": token_type}
        )

        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate a JWT token and return the claims if valid."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            
            # Check if token is valid in database
            if not self.token_store.is_token_valid(payload["jti"]):
                return None

            if payload["exp"] < datetime.utcnow().timestamp():
                return None

            return payload
        except jwt.InvalidTokenError:
            return None

    def hash_password(self, password: str) -> str:
        """
        Hashes a password using bcrypt.

        Args:
            password: The plain-text password to hash.

        Returns:
            A base64 encoded string representing the hashed password.
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return base64.b64encode(hashed).decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verifies a plain-text password against a stored bcrypt hash.

        Args:
            password: The plain-text password to verify.
            hashed_password: The base64 encoded bcrypt hash to verify against.

        Returns:
            True if the password matches the hash, False otherwise.
        """
        try:
            stored_hash = base64.b64decode(hashed_password.encode('utf-8'))
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except Exception:
            return False

    def create_credentials(self, identity: str, password: str) -> Tuple[bool, str]:
        """
        Create new credentials for a user/entity
        
        Returns:
            Tuple[bool, str]: (success, error_message)
        """
        # Validate password against policy
        is_valid, error_message = self.password_policy.validate_password(password)
        if not is_valid:
            return False, error_message

        password_hash = self.hash_password(password)
        success = self.credential_store.store_credentials(identity, password_hash)
        
        if success:
            self.security_logger.log_security_event(
                "credentials_created",
                {"identity": identity}
            )
            return True, ""
        return False, "Failed to store credentials"

    def change_password(self, identity: str, old_password: str,
                       new_password: str) -> Tuple[bool, str]:
        """
        Change a user's password
        
        Returns:
            Tuple[bool, str]: (success, error_message)
        """
        # Verify old password
        stored_creds = self.credential_store.get_credentials(identity)
        if not stored_creds or not self.verify_password(
            old_password, stored_creds["password_hash"]
        ):
            return False, "Invalid current password"

        # Validate new password against policy
        is_valid, error_message = self.password_policy.validate_password(
            new_password,
            stored_creds.get("password_history", [])
        )
        if not is_valid:
            return False, error_message

        # Update password
        new_hash = self.hash_password(new_password)
        success = self.credential_store.update_password(
            identity, new_hash, stored_creds["password_hash"]
        )

        if success:
            # Revoke all refresh tokens
            self.token_store.revoke_all_user_tokens(identity, "refresh")
            self.security_logger.log_password_change(identity, True)
            return True, ""
        return False, "Failed to update password"

    def revoke_token(self, token: str) -> bool:
        """Revoke a token before its expiration."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            success = self.token_store.revoke_token(payload["jti"])
            
            if success:
                self.security_logger.log_token_event(
                    "revoked",
                    payload["jti"],
                    payload["sub"]
                )
            return success
        except jwt.InvalidTokenError:
            return False

    def revoke_all_user_tokens(self, identity: str) -> bool:
        """Revoke all tokens for a user."""
        success = self.token_store.revoke_all_user_tokens(identity)
        if success:
            self.security_logger.log_security_event(
                "all_tokens_revoked",
                {"identity": identity}
            )
        return success

    def is_account_locked(self, identity: str) -> bool:
        """
        Checks if an account is currently locked due to excessive failed login attempts.

        An account is locked if the number of failed attempts reaches `max_failed_attempts`
        and the `lockout_duration` has not yet passed since the last attempt.

        Args:
            identity: The identifier of the account to check.

        Returns:
            True if the account is locked, False otherwise.
        """
        failed_attempts = self.credential_store.get_failed_attempts(identity)
        if failed_attempts >= self.max_failed_attempts:
            # Check if lockout duration has expired
            last_attempt = self.credential_store.get_last_attempt(identity)
            if last_attempt and (datetime.utcnow() - last_attempt).total_seconds() < self.lockout_duration:
                return True
        return False

    def record_failed_attempt(self, identity: str) -> None:
        """
        Records a failed authentication attempt for the given identity.

        This method increments the failed attempt counter for the specified identity
        in the credential store.

        Args:
            identity: The identifier of the account for which the failed attempt
                      is being recorded.
        """
        self.credential_store.record_failed_attempt(identity)

    def validate_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """
        Validates the format of credentials for password-based authentication.

        This method is used by the AuthenticationManager when it acts as the
        provider for password-based authentication. It checks if "identity" and
        "secret" (password) are present in the credentials dictionary.

        Args:
            credentials: A dictionary containing the credentials to validate.
                         Expected keys: "identity", "secret".

        Returns:
            A tuple (bool, str):
            - True if the credentials format is valid, False otherwise.
            - An error message string if validation fails, empty string otherwise.
        """
        identity = credentials.get("identity")
        password = credentials.get("secret")
        # ip_address = credentials.get("ip_address") # Result not used
        # user_agent = credentials.get("user_agent") # Result not used

        if not identity or not password:
            return False, "Missing identity or password"

        return True, ""

    def _handle_password_authentication(self, credentials: Dict) -> Optional[Dict]:
        """
        Handles password-based authentication for a user or entity.

        This method is called by the main `authenticate` method when the provider
        is "password". It checks for account lockout, verifies the provided
        identity and password against stored credentials, and if successful,
        generates and returns access and refresh tokens. Failed attempts are logged
        and recorded.

        Args:
            credentials: A dictionary containing authentication information.
                         Expected keys:
                         - "identity" (str): The user's identifier (username).
                         - "secret" (str): The user's password.
                         - "ip_address" (str, optional): Client's IP address.
                         - "user_agent" (str, optional): Client's user agent.

        Returns:
            Optional[Dict]: A dictionary containing token information if authentication
                            is successful:
                            - "access_token" (str)
                            - "refresh_token" (str)
                            - "token_type" (str): "bearer"
                            - "expires_in" (int): Access token lifetime in seconds.
                            - "identity" (str): The authenticated identity.
                            - "provider" (str): "password"
                            Returns None if authentication fails.
        """
        identity = credentials.get("identity")
        password = credentials.get("secret") # 'secret' is the key for password
        ip_address = credentials.get("ip_address")
        user_agent = credentials.get("user_agent")

        # Basic validation (already done by validate_credentials, but good for direct call safety)
        if not identity or not password:
            self.security_logger.log_authentication_attempt(
                identity or "unknown", False, ip_address, user_agent,
                details={"error": "Missing identity or password for password auth"}
            )
            return None

        # Check for account lockout
        if self.is_account_locked(identity):
            self.security_logger.log_authentication_attempt(
                identity, False, ip_address, user_agent,
                details={"error": "Account locked", "provider": "password"}
            )
            return None

        if self._verify_password_credentials(identity, password):
            # Reset failed attempts on successful login
            self.credential_store.reset_failed_attempts(identity)
            
            # Generate both access and refresh tokens
            # The main authenticate method will log the successful attempt
            access_token = self.generate_token(identity, "access", {"provider": "password", "identity": identity})
            refresh_token = self.generate_token(identity, "refresh", {"provider": "password"})


            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": self.token_expiry,
                "identity": identity, # Pass identity for logging in main auth
                "provider": "password"  # Pass provider for logging
            }
        
        # Record failed attempt
        self.record_failed_attempt(identity)
        # Logging of failed attempt is handled by the main authenticate method
        # based on the None return, but we can add specifics here if needed.
        # For now, the main `authenticate` logs it.
        return None

    def _verify_password_credentials(self, identity: str, password: str) -> bool:
        """
        Verifies the given identity and password against stored credentials.

        This is a helper method specifically for password-based authentication.
        It retrieves the stored password hash for the given identity and
        compares it with the provided password using `self.verify_password()`.

        Args:
            identity: The user's identifier.
            password: The user's plain-text password.

        Returns:
            True if the credentials are valid, False otherwise.
        """
        stored_creds = self.credential_store.get_credentials(identity)
        if not stored_creds:
            return False

        return self.verify_password(password, stored_creds["password_hash"])

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict]:
        """Generate a new access token using a refresh token.

        Args:
            refresh_token: The refresh token string.

        Returns:
            Optional[Dict]: A dictionary containing the new access token,
                            token type, and expiry if successful, None otherwise.
        """
        claims = self.validate_token(refresh_token)
        if not claims or claims.get("type") != "refresh":
            return None

        identity = claims["sub"]
        new_access_token = self.generate_token(identity, "access")

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": self.token_expiry
        }