"""
Basic usage example of Zero Trust Security Agent
"""

from zta_agent import initialize_agent
from datetime import datetime

def demonstrate_basic_usage():
    # Initialize the agent with default configuration
    print("Initializing Zero Trust Security Agent...")
    agent = initialize_agent()
    
    # Get individual components
    auth_manager = agent['auth_manager']
    policy_engine = agent['policy_engine']
    security_monitor = agent['security_monitor']
    
    # 1. Authentication Example
    print("\n1. Authentication Example:")
    # Create credentials for a test agent
    credentials = {
        "identity": "test_agent_1",
        "secret": "test_secret"
    }
    
    # Generate token
    token = auth_manager.authenticate(credentials)
    print(f"Generated token for test_agent_1: {token}")
    
    # Validate token
    claims = auth_manager.validate_token(token)
    print(f"Token validation result: {claims}")
    
    # 2. Policy Enforcement Example
    print("\n2. Policy Enforcement Example:")
    # Create a context for policy evaluation
    context = {
        "action_type": "execute_task",
        "resource": {
            "type": "read"
        },
        "source_agent": "internal_agent",
        "target_agent": "internal_worker",
        "claims": claims
    }
    
    # Evaluate policy
    is_allowed = policy_engine.evaluate(context)
    print(f"Action allowed by policy: {is_allowed}")
    
    # 3. Security Monitoring Example
    print("\n3. Security Monitoring Example:")
    # Record some security events
    security_monitor.record_event(
        "authentication_success",
        {"agent_id": "test_agent_1"},
        "INFO"
    )
    
    security_monitor.record_event(
        "policy_check",
        {
            "context": context,
            "result": is_allowed
        },
        "INFO"
    )
    
    # Retrieve and display events
    events = security_monitor.get_events(start_time=datetime.utcnow().replace(minute=0))
    print("\nRecent security events:")
    for event in events:
        print(f"- {event.event_type}: {event.details}")

if __name__ == "__main__":
    demonstrate_basic_usage()
