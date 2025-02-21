"""
Authentication Manager for Zero Trust Security Agent
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
import secrets
import bcrypt
import base64
import hmac
from .credential_store import CredentialStore

class AuthenticationManager:
    def __init__(self, config: Dict) -> None:
        self.secret_key = config.get("secret_key", secrets.token_hex(32))
        self.token_expiry = config.get("token_expiry", 3600)  # 1 hour default
        self.active_sessions: Dict[str, Dict] = {}
        self.max_failed_attempts = config.get("max_failed_attempts", 5)
        self.lockout_duration = config.get("lockout_duration", 300)  # 5 minutes
        self.credential_store = CredentialStore()

    def generate_token(self, identity: str, claims: Optional[Dict] = None) -> str:
        """Generate a JWT token for the given identity."""
        if claims is None:
            claims = {}

        payload = {
            "sub": identity,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=self.token_expiry),
            "jti": secrets.token_hex(16),  # Add unique token ID
            **claims
        }

        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate a JWT token and return the claims if valid."""
        try:
            # Check if token is revoked
            if token in self.active_sessions:
                return None

            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
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

    def is_account_locked(self, identity: str) -> bool:
        """Check if an account is locked due to too many failed attempts."""
        stored_creds = self.credential_store.get_credentials(identity)
        if not stored_creds:
            return False

        if stored_creds["is_locked"]:
            last_attempt = stored_creds["last_failed_attempt"]
            if last_attempt:
                lockout_time = last_attempt + timedelta(seconds=self.lockout_duration)
                if datetime.utcnow() < lockout_time:
                    return True
                # Reset failed attempts if lockout period has passed
                self.credential_store.reset_failed_attempts(identity)
        return False

    def record_failed_attempt(self, identity: str) -> None:
        """Record a failed authentication attempt."""
        stored_creds = self.credential_store.get_credentials(identity)
        if stored_creds:
            attempts = stored_creds["failed_attempts"] + 1
            is_locked = attempts >= self.max_failed_attempts
            self.credential_store.update_failed_attempts(identity, attempts, is_locked)
        else:
            # Create a new credential record for tracking failed attempts
            self.credential_store.store_credentials(
                identity=identity,
                password_hash=""  # Empty hash for non-existent users
            )
            self.credential_store.update_failed_attempts(identity, 1, False)

    def authenticate(self, credentials: Dict) -> Optional[str]:
        """Authenticate an entity and return a token if successful."""
        identity = credentials.get("identity")
        password = credentials.get("secret")

        if not identity or not password:
            return None

        # Check for account lockout
        if self.is_account_locked(identity):
            return None

        if self._verify_credentials(credentials):
            # Reset failed attempts on successful login
            self.credential_store.reset_failed_attempts(identity)
            return self.generate_token(identity)
        
        # Record failed attempt
        self.record_failed_attempt(identity)
        return None

    def _verify_credentials(self, credentials: Dict) -> bool:
        """Verify the provided credentials."""
        identity = credentials.get("identity")
        password = credentials.get("secret")

        if not identity or not password:
            return False

        stored_credentials = self.credential_store.get_credentials(identity)
        if not stored_credentials or not stored_credentials["password_hash"]:
            return False

        return self.verify_password(password, stored_credentials["password_hash"])

    def create_credentials(self, identity: str, password: str) -> bool:
        """
        Create new credentials for a user/entity
        
        Args:
            identity: The identity of the user/entity
            password: The plain text password to hash and store
            
        Returns:
            bool: True if successful, False otherwise
        """
        password_hash = self.hash_password(password)
        return self.credential_store.store_credentials(identity, password_hash)

    def revoke_token(self, token: str) -> bool:
        """Revoke a token before its expiration."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            self.active_sessions[token] = {
                "revoked_at": datetime.utcnow(),
                "subject": payload["sub"]
            }
            return True
        except jwt.InvalidTokenError:
            return False