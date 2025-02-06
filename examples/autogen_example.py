
import autogen
from zta_agent import initialize_agent

# Initialize ZTA components
zta_components = initialize_agent()
autogen_adapter = zta_components['autogen_adapter']

# Get authentication token
auth_manager = zta_components['auth_manager']
token = auth_manager.authenticate({
    "identity": "assistant_agent",
    "secret": "secret123"
})

# Create configuration for agents
config_list = [{'model': 'gpt-4'}]

# Create secure assistant
assistant = autogen.AssistantAgent(
    name="secure_assistant",
    system_message="I am a secure AI assistant.",
    llm_config={"config_list": config_list}
)

# Create secure user proxy
user_proxy = autogen.UserProxyAgent(
    name="secure_user",
    system_message="I am a secure user proxy.",
    code_execution_config={"work_dir": "coding"}
)

# Wrap message sending with security validation
original_send = assistant.send

def secure_send(message, recipient, request_reply=None, silent=False):
    # Validate communication
    if autogen_adapter.validate_agent_communication(
        source_agent=assistant.name,
        target_agent=recipient.name,
        message={"type": "text", "content": message},
        token=token
    ):
        return original_send(message, recipient, request_reply, silent)
    return "Communication denied by security policy"

assistant.send = secure_send

# Example usage
if __name__ == "__main__":
    # Initialize chat between agents
    user_proxy.initiate_chat(
        assistant,
        message="Let's solve a coding problem securely."
    )
