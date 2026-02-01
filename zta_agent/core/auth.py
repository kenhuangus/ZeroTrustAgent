"""
Authentication Manager for Zero Trust Security Agent
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
import secrets
import bcrypt
import base64
import hmac
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
        """Setup authentication providers based on configuration"""
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
        self.auth_providers["password"] = self

    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticate using the appropriate provider based on credentials
        
        Args:
            credentials: Dictionary containing:
                - provider: Authentication provider to use
                - Other provider-specific credentials
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
        auth_result = provider.authenticate(credentials)
        
        if auth_result:
            # Generate tokens
            access_token = self.generate_token(
                auth_result["identity"],
                "access",
                {"provider": provider_name, **auth_result}
            )
            refresh_token = self.generate_token(
                auth_result["identity"],
                "refresh",
                {"provider": provider_name}
            )

            self.security_logger.log_authentication_attempt(
                auth_result["identity"],
                True,
                credentials.get("ip_address"),
                credentials.get("user_agent"),
                details={"provider": provider_name}
            )

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": self.token_expiry,
                **auth_result
            }

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
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return base64.b64encode(hashed).decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
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
        """Check if an account is locked out."""
        failed_attempts = self.credential_store.get_failed_attempts(identity)
        if failed_attempts >= self.max_failed_attempts:
            # Check if lockout duration has expired
            last_attempt = self.credential_store.get_last_attempt(identity)
            if last_attempt and (datetime.utcnow() - last_attempt).total_seconds() < self.lockout_duration:
                return True
        return False

    def record_failed_attempt(self, identity: str) -> None:
        """Record a failed authentication attempt."""
        self.credential_store.record_failed_attempt(identity)

    def validate_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """Validate credentials format for password-based authentication."""
        identity = credentials.get("identity")
        password = credentials.get("secret")
        ip_address = credentials.get("ip_address")
        user_agent = credentials.get("user_agent")

        if not identity or not password:
            return False, "Missing identity or password"

        return True, ""

    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticate an entity and return tokens if successful.
        Returns both access and refresh tokens.
        """
        identity = credentials.get("identity")
        password = credentials.get("secret")
        ip_address = credentials.get("ip_address")
        user_agent = credentials.get("user_agent")

        if not identity or not password:
            return None

        # Check for account lockout
        if self.is_account_locked(identity):
            self.security_logger.log_authentication_attempt(
                identity, False, ip_address, user_agent
            )
            return None

        if self._verify_credentials(credentials):
            # Reset failed attempts on successful login
            self.credential_store.reset_failed_attempts(identity)
            
            # Generate both access and refresh tokens
            access_token = self.generate_token(identity, "access")
            refresh_token = self.generate_token(identity, "refresh")

            self.security_logger.log_authentication_attempt(
                identity, True, ip_address, user_agent,
                details={"provider": "password"}
            )

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": self.token_expiry,
                "identity": identity
            }
        
        # Record failed attempt
        self.record_failed_attempt(identity)
        self.security_logger.log_authentication_attempt(
            identity, False, ip_address, user_agent,
            details={"provider": "password"}
        )
        return None

    def _verify_credentials(self, credentials: Dict) -> bool:
        """Verify credentials for password-based authentication."""
        identity = credentials.get("identity")
        password = credentials.get("secret")

        stored_creds = self.credential_store.get_credentials(identity)
        if not stored_creds:
            return False

        return self.verify_password(password, stored_creds["password_hash"])

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict]:
        """Generate a new access token using a refresh token."""
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