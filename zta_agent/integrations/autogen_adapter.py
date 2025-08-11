"""
AutoGen Integration Adapter for Zero Trust Security Agent
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

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

        # Create a context for policy evaluation
        context = {
            "action_type": "send_message",
            "source_agent": source_agent,
            "target_agent": target_agent,
            "message": message,
            "claims": claims,
            "framework": "autogen"  # Framework context marker
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "communication_attempt",
            {"context": context, "allowed": is_allowed},
            "INFO"
        )

        return is_allowed

    def secure_message_exchange(self, message: Dict, sender_id: str, receiver_id: str, token: str) -> Optional[str]:
        """
        Executes a secure message exchange between sender and receiver using CrewAI's Agent and LLM.
        """
        # Validate the token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "message_exchange_failure",
                {"reason": "invalid_token", "sender_id": sender_id, "receiver_id": receiver_id},
                "ERROR"
            )
            return None

        # Construct the prompt from the message content
        prompt = message.get('content', '')

        # Use CrewAI's Agent and LLM for processing
        import os
        from crewai import Agent, LLM

        my_llm = LLM(
            api_key=os.getenv("OPENAI_API_KEY"),
            model="mistralai/Mixtral-8x7B-Instruct-v0.1"
        )

        # Instantiate an agent with the LLM (adjust parameters as needed)
        my_agent = Agent(
            name="secure_agent",
            system_message="You are a secure assistant.",
            llm=my_llm
        )

        try:
            # Execute the agent completion using the prompt. Adjust method call as needed.
            result = my_agent.complete(message=prompt)
            self.security_monitor.record_event(
                "message_exchange",
                {
                    "sender_id": sender_id,
                    "receiver_id": receiver_id,
                    "message": message,
                    "llm_result": result
                },
                "INFO"
            )
            return result
        except Exception as e:
            self.security_monitor.record_event(
                "llm_call_failure",
                {"error": str(e), "sender_id": sender_id, "receiver_id": receiver_id},
                "ERROR"
            )
            return None