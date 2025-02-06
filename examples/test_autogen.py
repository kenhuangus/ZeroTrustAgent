
import autogen
from zta_agent import initialize_agent

def test_autogen_integration():
    # Initialize ZTA components
    zta_components = initialize_agent()
    autogen_adapter = zta_components['autogen_adapter']
    
    # Get authentication token
    auth_manager = zta_components['auth_manager']
    token = auth_manager.authenticate({
        "identity": "assistant_agent",
        "secret": "secret123"
    })
    
    # Test conversation validation
    conversation_id = "test_conv_1"
    participants = {
        "assistant": "secure_assistant",
        "user": "secure_user"
    }
    
    is_valid = autogen_adapter.validate_conversation(
        conversation_id=conversation_id,
        participants=participants,
        token=token
    )
    
    print(f"Conversation validation result: {is_valid}")

if __name__ == "__main__":
    test_autogen_integration()
