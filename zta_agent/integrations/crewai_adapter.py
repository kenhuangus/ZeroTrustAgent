"""
CrewAI Integration Adapter for Zero Trust Security Agent
"""

# Begin added lines (to resolve relative import issues)
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
# End added lines

from typing import Any, Dict, Optional
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor

class CrewAIAdapter:
    def __init__(self, auth_manager: AuthenticationManager, 
                 policy_engine: PolicyEngine,
                 security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor

    def validate_agent_action(self, agent_id: str, action: Dict, token: str) -> bool:
        """Validate if an agent can perform a specific action."""
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_access_attempt",
                {"agent_id": agent_id, "action": action},
                "WARNING"
            )
            return False

        # Create context for policy evaluation
        context = {
            "agent_id": agent_id,
            "action_type": action.get("type"),
            "resource": action.get("resource"),
            "claims": claims,
            "framework": "crewai"
        }

        # Evaluate policies
        is_allowed = self.policy_engine.evaluate(context)
        
        # Record the access attempt
        self.security_monitor.record_event(
            "action_validation",
            {
                "agent_id": agent_id,
                "action": action,
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        return is_allowed

    def secure_task_execution(self, task: Dict, agent_id: str, token: str) -> bool:
        # Validate token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "task_execution_failed",
                {"reason": "invalid_token", "agent_id": agent_id},
                "WARNING"
            )
            return False

        # Check policy
        context = {
            "action_type": "execute_task",
            "resource": task,
            "agent_id": agent_id,
            "claims": claims
        }

        is_allowed = self.policy_engine.evaluate(context)

        self.security_monitor.record_event(
            "task_execution_attempt",
            {"task": task, "agent_id": agent_id, "allowed": is_allowed},
            "INFO"
        )
        
        return is_allowed

    def validate_agent_communication(self, 
                                  source_agent: str, 
                                  target_agent: str, 
                                  message: Dict,
                                  token: str) -> bool:
        """Validate agent-to-agent communication."""
        claims = self.auth_manager.validate_token(token)
        if not claims:
            return False

        context = {
            "source_agent": source_agent,
            "target_agent": target_agent,
            "message_type": message.get("type"),
            "claims": claims,
            "framework": "crewai"
        }

        is_allowed = self.policy_engine.evaluate(context)
        
        self.security_monitor.record_event(
            "agent_communication",
            {
                "source_agent": source_agent,
                "target_agent": target_agent,
                "message_type": message.get("type"),
                "allowed": is_allowed
            },
            "INFO" if is_allowed else "WARNING"
        )
        
        return is_allowed