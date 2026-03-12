"""
Custom Exception Classes for Zero Trust Security Agent

This module provides comprehensive exception handling for the ZeroTrustAgent.
All exceptions inherit from appropriate base classes and provide detailed context.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


class AuthenticationError(Exception):
    """Base exception for authentication errors.
    
    Attributes:
        message: Human-readable error message
        details: Additional context about the error
        identity: The identity that failed authentication (if applicable)
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        identity: Optional[str] = None
    ) -> None:
        super().__init__(message)
        self.details = details or {}
        self.identity = identity
        self.timestamp = __import__('datetime').datetime.utcnow()

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.identity:
            parts.append(f"identity={self.identity}")
        if self.details:
            parts.append(f"details={self.details}")
        return " | ".join(parts)


class TokenExpiredError(AuthenticationError):
    """Exception raised when a token has expired.
    
    Attributes:
        token_type: Type of token that expired (access, refresh)
        expiry_time: When the token expired
    """
    
    def __init__(
        self,
        token_type: str = "access",
        expiry_time: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"{token_type.capitalize()} token has expired"
        super().__init__(message, details)
        self.token_type = token_type
        self.expiry_time = expiry_time


class InvalidCredentialsError(AuthenticationError):
    """Exception raised when credentials are invalid.
    
    Attributes:
        reason: Specific reason why credentials are invalid
        attempts: Number of failed attempts
    """
    
    def __init__(
        self,
        reason: str = "Invalid credentials provided",
        attempts: int = 0,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = reason
        super().__init__(message, details)
        self.reason = reason
        self.attempts = attempts


class AccountLockedError(AuthenticationError):
    """Exception raised when an account is locked due to too many failed attempts.
    
    Attributes:
        lockout_duration: Duration of the lockout in seconds
        unlock_time: When the account will be unlocked
        max_attempts: Maximum allowed failed attempts
    """
    
    def __init__(
        self,
        identity: str,
        lockout_duration: int = 300,
        max_attempts: int = 5,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Account {identity} is locked. Maximum failed attempts ({max_attempts}) exceeded"
        super().__init__(message, details, identity)
        self.lockout_duration = lockout_duration
        self.max_attempts = max_attempts


class PasswordPolicyError(AuthenticationError):
    """Exception raised when password does not meet policy requirements.
    
    Attributes:
        violations: List of policy violations
        policy_name: Name of the policy that was violated
    """
    
    def __init__(
        self,
        violations: List[str],
        policy_name: str = "default",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Password does not meet policy requirements: {', '.join(violations)}"
        super().__init__(message, details)
        self.violations = violations
        self.policy_name = policy_name


class PolicyViolationError(Exception):
    """Exception raised when a policy check fails.
    
    Attributes:
        policy_name: Name of the policy that was violated
        context: Context that caused the policy violation
        action: Action that was denied (allow/deny)
    """
    
    def __init__(
        self,
        policy_name: str,
        context: Dict[str, Any],
        action: str = "deny"
    ) -> None:
        self.policy_name = policy_name
        self.context = context
        self.action = action
        message = f"Policy {policy_name} {action} access"
        super().__init__(message)

    def __str__(self) -> str:
        return f"{super().__str__()} (policy={self.policy_name}, context={self.context})"


class SecurityMonitorError(Exception):
    """Base exception for security monitoring errors.
    
    Attributes:
        event_type: Type of security event that caused the error
        severity: Severity level of the event
    """
    
    def __init__(
        self,
        message: str,
        event_type: Optional[str] = None,
        severity: str = "error"
    ) -> None:
        super().__init__(message)
        self.event_type = event_type
        self.severity = severity


class RateLimitExceededError(SecurityMonitorError):
    """Exception raised when rate limit has been exceeded.
    
    Attributes:
        limit_type: Type of rate limit (auth, api)
        window_size: Size of the rate limit window in seconds
        max_requests: Maximum allowed requests in the window
        retry_after: Seconds until the rate limit is reset
    """
    
    def __init__(
        self,
        limit_type: str = "api",
        window_size: int = 60,
        max_requests: int = 100,
        retry_after: int = 60,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Rate limit exceeded for {limit_type}. Max {max_requests} requests per {window_size}s"
        super().__init__(message, event_type="rate_limit_exceeded")
        self.limit_type = limit_type
        self.window_size = window_size
        self.max_requests = max_requests
        self.retry_after = retry_after


class ConfigurationError(Exception):
    """Exception raised when configuration is invalid.
    
    Attributes:
        config_key: The configuration key that is invalid
        expected_type: Expected type of the configuration value
        actual_value: The actual value that was provided
    """
    
    def __init__(
        self,
        config_key: str,
        expected_type: str,
        actual_value: Any = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Invalid configuration for '{config_key}'. Expected {expected_type}"
        super().__init__(message)
        self.config_key = config_key
        self.expected_type = expected_type
        self.actual_value = actual_value
        self.details = details or {}


class CredentialStoreError(Exception):
    """Exception raised when credential store operations fail.
    
    Attributes:
        operation: The operation that failed
        identity: The identity involved in the operation
    """
    
    def __init__(
        self,
        operation: str,
        identity: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Credential store operation '{operation}' failed"
        super().__init__(message)
        self.operation = operation
        self.identity = identity
        self.details = details or {}


class TokenStoreError(Exception):
    """Exception raised when token store operations fail.
    
    Attributes:
        operation: The operation that failed
        token_jti: The token JTI involved in the operation
    """
    
    def __init__(
        self,
        operation: str,
        token_jti: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Token store operation '{operation}' failed"
        super().__init__(message)
        self.operation = operation
        self.token_jti = token_jti
        self.details = details or {}


class BehavioralAnalyticsError(Exception):
    """Exception raised when behavioral analytics operations fail.
    
    Attributes:
        operation: The operation that failed
        user_id: The user involved in the operation
    """
    
    def __init__(
        self,
        operation: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"Behavioral analytics operation '{operation}' failed"
        super().__init__(message)
        self.operation = operation
        self.user_id = user_id
        self.details = details or {}


class LLMAnalysisError(Exception):
    """Exception raised when LLM-based security analysis fails.
    
    Attributes:
        provider: The LLM provider that failed
        error_type: Type of error that occurred
    """
    
    def __init__(
        self,
        provider: str = "unknown",
        error_type: str = "analysis_failed",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        message = f"LLM analysis failed for provider '{provider}'"
        super().__init__(message)
        self.provider = provider
        self.error_type = error_type
        self.details = details or {}


@dataclass
class SecurityAlert:
    """Data class representing a security alert.
    
    Attributes:
        alert_id: Unique identifier for the alert
        timestamp: When the alert was generated
        alert_type: Type of security alert
        severity: Alert severity level
        source_ip: Source IP address involved
        identity: Identity involved (if applicable)
        details: Additional alert details
        recommendations: List of recommended actions
    """
    alert_id: str = field(default_factory=__import__('secrets').token_hex)
    timestamp: __import__('datetime').datetime = field(default_factory=__import__('datetime').datetime.utcnow)
    alert_type: str = "general"
    severity: str = "warning"
    source_ip: Optional[str] = None
    identity: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "identity": self.identity,
            "details": self.details,
            "recommendations": self.recommendations
        }


# Exception hierarchy for easy handling
__all__ = [
    # Authentication exceptions
    "AuthenticationError",
    "TokenExpiredError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "PasswordPolicyError",
    
    # Policy exceptions
    "PolicyViolationError",
    
    # Security monitoring exceptions
    "SecurityMonitorError",
    "RateLimitExceededError",
    
    # Configuration exceptions
    "ConfigurationError",
    
    # Store exceptions
    "CredentialStoreError",
    "TokenStoreError",
    
    # Analytics exceptions
    "BehavioralAnalyticsError",
    "LLMAnalysisError",
    
    # Data classes
    "SecurityAlert",
]