import unittest
import re
from zta_agent.core.policy import PolicyEngine, Policy

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.base_config = {
            "policies": [
                {
                    "name": "AllowAdminsFullAccess",
                    "conditions": {"user.role": {"eq": "admin"}},
                    "effect": "allow",
                    "priority": 100
                },
                {
                    "name": "AllowResearchersRead",
                    "conditions": {
                        "user.role": {"eq": "researcher"},
                        "action.type": {"in": ["read", "list"]}
                    },
                    "effect": "allow",
                    "priority": 50
                },
                {
                    "name": "DenyInternsSensitiveDataHighPriority", # Explicit deny for testing precedence
                    "conditions": {
                        "user.role": {"eq": "intern"},
                        "resource.sensitivity": {"eq": "high"}
                    },
                    "effect": "deny", # This will be treated as "not allow" by current engine
                    "priority": 70 
                },
                {
                    "name": "AllowInternsLowSensitivityRead",
                     "conditions": {
                        "user.role": {"eq": "intern"},
                        "resource.sensitivity": {"eq": "low"},
                        "action.type": {"eq": "read"}
                    },
                    "effect": "allow",
                    "priority": 60
                }
            ]
        }
        self.policy_engine = PolicyEngine(self.base_config)

    # 1. Initialization and Policy Loading
    def test_initialization_and_policy_loading(self):
        self.assertEqual(len(self.policy_engine.policies), 4)
        # Check sorting by priority (descending)
        self.assertEqual(self.policy_engine.policies[0].name, "AllowAdminsFullAccess") # 100
        self.assertEqual(self.policy_engine.policies[1].name, "DenyInternsSensitiveDataHighPriority") # 70
        self.assertEqual(self.policy_engine.policies[2].name, "AllowInternsLowSensitivityRead") # 60
        self.assertEqual(self.policy_engine.policies[3].name, "AllowResearchersRead") # 50

    def test_initialization_with_empty_policy_config(self):
        engine = PolicyEngine({"policies": []})
        self.assertEqual(len(engine.policies), 0)
        context = {"user.role": "any", "action.type": "any"}
        self.assertFalse(engine.evaluate(context)) # Default deny

    def test_initialization_with_no_policies_key(self):
        engine = PolicyEngine({})
        self.assertEqual(len(engine.policies), 0)
        context = {"user.role": "any", "action.type": "any"}
        self.assertFalse(engine.evaluate(context))

    # 2. Policy Evaluation (evaluate method)
    def test_evaluate_allow_admin(self):
        context = {"user": {"role": "admin"}, "action": {"type": "any"}}
        self.assertTrue(self.policy_engine.evaluate(context))

    def test_evaluate_allow_researcher_read(self):
        context = {"user": {"role": "researcher"}, "action": {"type": "read"}}
        self.assertTrue(self.policy_engine.evaluate(context))

    def test_evaluate_deny_researcher_write(self):
        context = {"user": {"role": "researcher"}, "action": {"type": "write"}}
        # No allow policy matches for researcher write
        self.assertFalse(self.policy_engine.evaluate(context))

    def test_evaluate_default_deny_no_matching_policy(self):
        context = {"user": {"role": "unknown"}, "action": {"type": "read"}}
        self.assertFalse(self.policy_engine.evaluate(context))

    def test_evaluate_priority_deny_overrides_allow(self):
        # DenyInternsSensitiveDataHighPriority (70) vs AllowInternsLowSensitivityRead (60)
        # If context matches DenyInternsSensitiveDataHighPriority, it should deny.
        context_intern_sensitive = {
            "user": {"role": "intern"},
            "resource": {"sensitivity": "high"},
            "action": {"type": "read"} # Action doesn't matter for the deny policy here
        }
        # Current engine: finds the deny policy, it returns False because effect is not "allow".
        self.assertFalse(self.policy_engine.evaluate(context_intern_sensitive))

    def test_evaluate_priority_allow_takes_precedence_if_deny_does_not_match(self):
        # Context matches AllowInternsLowSensitivityRead (60) but not DenyInternsSensitiveDataHighPriority (70)
        context_intern_low_sensitivity_read = {
            "user": {"role": "intern"},
            "resource": {"sensitivity": "low"},
            "action": {"type": "read"}
        }
        self.assertTrue(self.policy_engine.evaluate(context_intern_low_sensitivity_read))

    def test_evaluate_allow_admin_overrides_lower_priority_deny_if_both_match(self):
        # Add a general deny policy with lower priority than admin allow
        low_priority_deny_config = {
            "policies": [
                {"name": "AllowAdmins", "conditions": {"user.role": {"eq": "admin"}}, "effect": "allow", "priority": 100},
                {"name": "DenyAllForAdminsResource", "conditions": {"resource.type": {"eq": "specific"}}, "effect": "deny", "priority": 10}
            ]
        }
        engine = PolicyEngine(low_priority_deny_config)
        context = {"user": {"role": "admin"}, "resource": {"type": "specific"}}
        # Admin allow is higher priority, so it should allow even if a lower priority deny also matches context
        self.assertTrue(engine.evaluate(context))


    # 3. Condition Matching (_matches_conditions and _evaluate_condition)
    def test_condition_eq_match(self):
        context = {"user": {"name": "Alice"}}
        policy = Policy("p1", {"user.name": {"eq": "Alice"}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_eq_no_match(self):
        context = {"user": {"name": "Bob"}}
        policy = Policy("p1", {"user.name": {"eq": "Alice"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))
    
    def test_condition_eq_case_sensitive(self):
        context = {"user": {"name": "alice"}}
        policy = Policy("p1", {"user.name": {"eq": "Alice"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_ne_match(self):
        context = {"user": {"status": "active"}}
        policy = Policy("p1", {"user.status": {"ne": "inactive"}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_ne_no_match(self):
        context = {"user": {"status": "inactive"}}
        policy = Policy("p1", {"user.status": {"ne": "inactive"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_gt_match(self):
        context = {"request": {"retries": 5}}
        policy = Policy("p1", {"request.retries": {"gt": 3}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_gt_no_match(self):
        context = {"request": {"retries": 3}}
        policy = Policy("p1", {"request.retries": {"gt": 3}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_lt_match(self):
        context = {"item": {"count": 2}}
        policy = Policy("p1", {"item.count": {"lt": 5}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))
    
    def test_condition_gte_match(self):
        context = {"item": {"count": 5}}
        policy = Policy("p1", {"item.count": {"gte": 5}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_lte_match(self):
        context = {"item": {"count": 5}}
        policy = Policy("p1", {"item.count": {"lte": 5}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_in_match_list(self):
        context = {"action": {"type": "read"}}
        policy = Policy("p1", {"action.type": {"in": ["read", "list", "view"]}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_in_no_match_list(self):
        context = {"action": {"type": "write"}}
        policy = Policy("p1", {"action.type": {"in": ["read", "list"]}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_not_in_match_list(self):
        context = {"action": {"type": "delete"}}
        policy = Policy("p1", {"action.type": {"not_in": ["read", "write"]}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_not_in_no_match_list(self):
        context = {"action": {"type": "read"}}
        policy = Policy("p1", {"action.type": {"not_in": ["read", "write"]}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_regex_match(self):
        context = {"resource": {"name": "document_123.txt"}}
        policy = Policy("p1", {"resource.name": {"regex": "^document_\\d+\\.txt$"}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_regex_no_match(self):
        context = {"resource": {"name": "image.jpg"}}
        policy = Policy("p1", {"resource.name": {"regex": "^document_\\d+\\.txt$"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_contains_match_string(self):
        context = {"log": {"message": "Error: Critical system failure"}}
        policy = Policy("p1", {"log.message": {"contains": "Critical"}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_contains_no_match_string(self):
        context = {"log": {"message": "Status: OK"}}
        policy = Policy("p1", {"log.message": {"contains": "Critical"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))
        
    def test_condition_contains_match_list(self):
        context = {"request": {"tags": ["urgent", "finance", "external"]}}
        policy = Policy("p1", {"request.tags": {"contains": "finance"}}, "allow", 1) # "finance" is in the list
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_contains_no_match_list(self):
        context = {"request": {"tags": ["internal", "report"]}}
        policy = Policy("p1", {"request.tags": {"contains": "finance"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_key_not_in_context(self):
        context = {"user": {"id": "user1"}} # 'user.role' is missing
        policy = Policy("p1", {"user.role": {"eq": "admin"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_nested_key_match(self):
        context = {"request": {"headers": {"X-User-ID": "alice"}}}
        policy = Policy("p1", {"request.headers.X-User-ID": {"eq": "alice"}}, "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_condition_nested_key_no_match_intermediate_missing(self):
        context = {"request": {}} # 'headers' is missing
        policy = Policy("p1", {"request.headers.X-User-ID": {"eq": "alice"}}, "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_multiple_conditions_all_match(self):
        context = {"user": {"role": "researcher"}, "action": {"type": "read"}}
        policy = Policy("p1", 
                        {"user.role": {"eq": "researcher"}, "action.type": {"eq": "read"}}, 
                        "allow", 1)
        self.assertTrue(self.policy_engine._matches_conditions(context, policy.conditions))

    def test_multiple_conditions_one_no_match(self):
        context = {"user": {"role": "researcher"}, "action": {"type": "write"}}
        policy = Policy("p1", 
                        {"user.role": {"eq": "researcher"}, "action.type": {"eq": "read"}}, 
                        "allow", 1)
        self.assertFalse(self.policy_engine._matches_conditions(context, policy.conditions))

    # 4. Policy Management
    def test_add_policy(self):
        new_policy_dict = {
            "name": "AllowSpecificUser",
            "conditions": {"user.id": {"eq": "special_user"}},
            "effect": "allow",
            "priority": 200 # Highest priority
        }
        self.policy_engine.add_policy(new_policy_dict)
        self.assertEqual(len(self.policy_engine.policies), 5)
        self.assertEqual(self.policy_engine.policies[0].name, "AllowSpecificUser")
        
        context = {"user": {"id": "special_user"}}
        self.assertTrue(self.policy_engine.evaluate(context))
        
        # Check if it overrides admin policy for a generic admin context due to higher priority
        admin_context = {"user": {"role": "admin", "id": "not_special_user"}} # Original admin policy would allow
        self.assertTrue(self.policy_engine.evaluate(admin_context)) # Still true because new policy doesn't match

        specific_admin_context = {"user": {"role": "admin", "id": "special_user"}}
        self.assertTrue(self.policy_engine.evaluate(specific_admin_context)) # New policy allows


    def test_add_policy_retains_sorting(self):
        new_policy_dict = {
            "name": "DenyAuditLogs",
            "conditions": {"resource.type": {"eq": "audit_log"}},
            "effect": "deny", 
            "priority": 75 # Between Admin (100) and DenyInterns (70)
        }
        self.policy_engine.add_policy(new_policy_dict)
        self.assertEqual(self.policy_engine.policies[0].name, "AllowAdminsFullAccess") #100
        self.assertEqual(self.policy_engine.policies[1].name, "DenyAuditLogs") #75
        self.assertEqual(self.policy_engine.policies[2].name, "DenyInternsSensitiveDataHighPriority") #70

    def test_remove_policy_success(self):
        self.assertTrue(self.policy_engine.remove_policy("AllowResearchersRead"))
        self.assertEqual(len(self.policy_engine.policies), 3)
        self.assertNotIn("AllowResearchersRead", [p.name for p in self.policy_engine.policies])
        
        context = {"user": {"role": "researcher"}, "action": {"type": "read"}}
        self.assertFalse(self.policy_engine.evaluate(context)) # Should now be denied

    def test_remove_policy_non_existent(self):
        self.assertFalse(self.policy_engine.remove_policy("NonExistentPolicy"))
        self.assertEqual(len(self.policy_engine.policies), 4) # Count remains same

    # 5. Unsupported Operator
    def test_evaluate_condition_unsupported_operator(self):
        with self.assertRaisesRegex(ValueError, "Unsupported operator: 'invalid_op'"):
            self.policy_engine._evaluate_condition("value", {"invalid_op": "target"})

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
