
import autogen
from zta_agent import initialize_agent

def test_autogen_integration():
    # Initialize ZTA components
    zta_components = initialize_agent()
    auth_manager = zta_components['auth_manager']
    autogen_adapter = zta_components['autogen_adapter']
    
    # Get authentication token
    token = auth_manager.authenticate({
        "identity": "assistant",
        "secret": "test_secret"
    })
    
    # Test message validation
    message = {
        "type": "text",
        "content": "Hello, let's solve a problem"
    }
    
    result = autogen_adapter.validate_agent_communication(
        source_agent="assistant",
        target_agent="user",
        message=message,
        token=token
    )
    
    print(f"AutoGen Integration Test Result: {result}")

if __name__ == "__main__":
    test_autogen_integration()
