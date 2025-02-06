"""
AutoGen Integration Adapter for Zero Trust Security Agent
"""

from typing import Any, Dict, Optional
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor

class AutoGenAdapter:
    def __init__(self, auth_manager: AuthenticationManager,
                 policy_engine: PolicyEngine,
                 security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor

    def validate_agent_communication(self, source_agent: str, 
                                   target_agent: str,
                                   message: Dict,
                                   token: str) -> bool:
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "communication_failed",
                {"reason": "invalid_token", "source": source_agent},
                "WARNING"
            )
            return False

        # Check policy with framework context
        context = {
            "action_type": "send_message",
            "source_agent": source_agent,
            "target_agent": target_agent,
            "message": message,
            "claims": claims,
            "framework": "autogen"  # Add framework context
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "communication_attempt",
            {"context": context, "allowed": is_allowed},
            "INFO"
        )

        return is_allowed

    def secure_message_exchange(self, 
                              message: Dict,
                              sender_id: str,
                              receiver_id: str,
                              token: str) -> Optional[Dict]:
        """Secure message exchange between agents."""
        if not self.validate_agent_communication(sender_id, receiver_id, message, token):
            return None

        # Record message exchange
        self.security_monitor.record_event(
            "message_exchange",
            {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "message_type": message.get("type"),
                "framework": "autogen"  # Add framework context
            }
        )

        return message