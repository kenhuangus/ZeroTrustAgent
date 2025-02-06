"""
AutoGen Integration Adapter for Zero Trust Security Agent
"""

from typing import Any, Dict, Optional
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor

class AutoGenAdapter:
    def __init__(self, 
                 auth_manager: AuthenticationManager,
                 policy_engine: PolicyEngine,
                 security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor

    def validate_conversation(self, 
                            conversation_id: str, 
                            participants: Dict,
                            token: str) -> bool:
        """Validate if a conversation can be initiated."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_conversation_attempt",
                {"conversation_id": conversation_id, "participants": participants},
                "WARNING"
            )
            return False

        context = {
            "conversation_id": conversation_id,
            "participants": participants,
            "claims": claims,
            "framework": "autogen"
        }

        is_allowed = self.policy_engine.evaluate(context)
        
        self.security_monitor.record_event(
            "conversation_validation",
            {
                "conversation_id": conversation_id,
                "participants": participants,
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed

    def secure_message_exchange(self, 
                              message: Dict,
                              sender_id: str,
                              receiver_id: str,
                              token: str) -> Optional[Dict]:
        """Secure message exchange between agents."""
        if not self.validate_message(sender_id, receiver_id, message, token):
            return None

        # Record message exchange
        self.security_monitor.record_event(
            "message_exchange",
            {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "message_type": message.get("type")
            }
        )

        return message

    def validate_message(self,
                        sender_id: str,
                        receiver_id: str,
                        message: Dict,
                        token: str) -> bool:
        """Validate if a message can be sent between agents."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        context = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "message_type": message.get("type"),
            "claims": claims,
            "framework": "autogen"
        }

        is_allowed = self.policy_engine.evaluate(context)
        
        self.security_monitor.record_event(
            "message_validation",
            {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "message_type": message.get("type"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed

    def validate_function_call(self,
                             agent_id: str,
                             function_name: str,
                             parameters: Dict,
                             token: str) -> bool:
        """Validate if an agent can call a specific function."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        context = {
            "agent_id": agent_id,
            "function_name": function_name,
            "parameters": parameters,
            "claims": claims,
            "framework": "autogen"
        }

        is_allowed = self.policy_engine.evaluate(context)
        
        self.security_monitor.record_event(
            "function_call_validation",
            {
                "agent_id": agent_id,
                "function_name": function_name,
                "parameters": parameters,
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )

        return is_allowed
