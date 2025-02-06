"""
Policy Engine for Zero Trust Security Agent
"""

from typing import Dict, List, Any
from dataclasses import dataclass
import re

@dataclass
class Policy:
    name: str
    conditions: Dict
    effect: str
    priority: int

class PolicyEngine:
    def __init__(self, config: Dict):
        self.policies = self._load_policies(config)

    def _load_policies(self, config: Dict) -> List[Policy]:
        """Load policies from configuration."""
        policies = []
        for policy_config in config.get("policies", []):
            policy = Policy(
                name=policy_config["name"],
                conditions=policy_config["conditions"],
                effect=policy_config["effect"],
                priority=policy_config.get("priority", 0)
            )
            policies.append(policy)
        return sorted(policies, key=lambda x: x.priority, reverse=True)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate policies against the given context."""
        for policy in self.policies:
            if self._matches_conditions(policy.conditions, context):
                return policy.effect.lower() == "allow"
        return False  # Default deny if no policy matches

    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def _matches_conditions(self, conditions: Dict, context: Dict) -> bool:
        """Check if context matches policy conditions."""
        for key, condition in conditions.items():
            context_value = self._get_nested_value(context, key)
            if context_value is None:
                return False

            if isinstance(condition, dict):
                operator = list(condition.keys())[0]
                value = condition[operator]

                if not self._evaluate_condition(context_value, operator, value):
                    return False
            else:
                if context_value != condition:
                    return False

        return True

    def _evaluate_condition(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate a single condition with an operator."""
        operators = {
            "eq": lambda x, y: x == y,
            "ne": lambda x, y: x != y,
            "gt": lambda x, y: x > y,
            "lt": lambda x, y: x < y,
            "gte": lambda x, y: x >= y,
            "lte": lambda x, y: x <= y,
            "in": lambda x, y: x in y,
            "not_in": lambda x, y: x not in y,
            "regex": lambda x, y: bool(re.match(y, str(x))),
            "contains": lambda x, y: y in x
        }

        if operator not in operators:
            raise ValueError(f"Unsupported operator: {operator}")

        return operators[operator](actual_value, expected_value)

    def add_policy(self, policy: Policy) -> None:
        """Add a new policy to the engine."""
        self.policies.append(policy)
        self.policies.sort(key=lambda x: x.priority, reverse=True)

    def remove_policy(self, policy_name: str) -> bool:
        """Remove a policy by name."""
        initial_length = len(self.policies)
        self.policies = [p for p in self.policies if p.name != policy_name]
        return len(self.policies) < initial_length