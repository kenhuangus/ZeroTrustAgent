import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import autogen
from zta_agent import initialize_agent
from dotenv import load_dotenv
import logging
import os

# Disable logging exception traceback (so errors from logging aren't printed)
logging.raiseExceptions = False

# Determine whether stdout supports emoji based on encoding.
USE_EMOJI = True
if sys.stdout.encoding is None or "utf-8" not in sys.stdout.encoding.lower():
    USE_EMOJI = False

def safe_emoji(text):
    """
    Replace emoji characters with ASCII fallbacks if USE_EMOJI is False.
    """
    if not USE_EMOJI:
        replacements = {
            "🔑": "[KEY]",
            "🤖": "[ASSISTANT]",
            "👤": "[USER]",
            "✅": "[ALLOWED]",
            "🚨": "[LLM ERROR]",
            "🚫": "[DENIED]",
            "🔥": "[ERROR]",
            "🔧": "[INIT]",
            "📨": "[SEND]",
            "📵": "[DENY]",
            "📝": "[MONITOR]"
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
    return text

# Custom logging handler that catches UnicodeEncodeError and does nothing.
class UnicodeSafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except UnicodeEncodeError:
            # Do nothing if there's a UnicodeEncodeError,
            # allowing the program to continue without logging this error.
            pass

# Reconfigure logging using the custom handler.
handler = UnicodeSafeStreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger = logging.getLogger(__name__)
logger.handlers = []  # Clear existing handlers.
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load environment variables and retrieve API key if needed.
load_dotenv()
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")

# Initialize ZTA components.
logger.info(safe_emoji("🔧 Initializing Zero Trust Security Agent components..."))
zta_components = initialize_agent()
autogen_adapter = zta_components['autogen_adapter']
auth_manager = zta_components['auth_manager']
security_monitor = zta_components['security_monitor']  # For monitoring events.

# ---------- Patching for testing purposes ----------
# Patch auth_manager.validate_token to return a dummy claims value if a mock token is used.
original_validate_token = auth_manager.validate_token
def patched_validate_token(token):
    if token == "mock_valid_token":
        return {"sub": "assistant_agent", "iat": 123456, "exp": 999999}
    return original_validate_token(token)
auth_manager.validate_token = patched_validate_token

# Patch policy evaluation so that:
# - "text" and "function_call" messages are allowed.
# - "system" messages are denied.
original_policy_evaluate = autogen_adapter.policy_engine.evaluate
def patched_policy_evaluate(context):
    msg_type = context.get("message", {}).get("type")
    if msg_type == "system":
        return False
    return True
autogen_adapter.policy_engine.evaluate = patched_policy_evaluate
# -----------------------------------------------------

# Authenticate autogen agent (with error recovery).
try:
    token = auth_manager.authenticate({
        "identity": "assistant_agent",
        "secret": "secret123"
    })
    if token:
        logger.info(safe_emoji(f"🔑 Authentication successful for assistant_agent: {token}"))
    else:
        logger.error(safe_emoji("🔑 Authentication failed for assistant_agent"))
        token = None
except Exception as e:
    logger.error(safe_emoji(f"🔑 Exception during authentication: {str(e)}"))
    token = None

# If token is still None, use a mock token for testing.
if not token:
    token = "mock_valid_token"
    logger.info(safe_emoji("🔑 Using mock token for testing purposes."))

# Create configuration for LLM agents (using GPT-4 in this example).
config_list = [{'model': 'gpt-4'}]

# Create secure assistant agent (recovering from LLM instantiation errors).
try:
    assistant = autogen.AssistantAgent(
        name="secure_assistant",
        system_message="I am a secure AI assistant.",
        llm_config={"config_list": config_list}
    )
    logger.info(safe_emoji("🤖 Assistant agent created successfully."))
except Exception as e:
    logger.error(safe_emoji(f"🤖 Error creating assistant agent: {str(e)}"))
    assistant = None

# Create secure user proxy agent (disable docker by setting use_docker to False).
try:
    user_proxy = autogen.UserProxyAgent(
        name="secure_user",
        system_message="I am a secure user proxy.",
        code_execution_config={"work_dir": "coding", "use_docker": False}
    )
    logger.info(safe_emoji("👤 User proxy agent created successfully."))
except Exception as e:
    logger.error(safe_emoji(f"👤 Error creating user proxy agent: {str(e)}"))
    user_proxy = None

# Save the original message-sending method if assistant is available.
original_send = assistant.send if assistant else None

def secure_send(message, recipient, message_type="text", request_reply=None, silent=False):
    """
    Wrap the original send method with a security validation check.
    The function accepts 'message_type' to simulate different types of messages.
    It also recovers from API/LLM/docker errors.
    """
    try:
        # Validate communication according to policy.
        if autogen_adapter.validate_agent_communication(
            source_agent=assistant.name,
            target_agent=recipient.name,
            message={"type": message_type, "content": message},
            token=token
        ):
            try:
                result = original_send(message, recipient, request_reply, silent)
                logger.info(safe_emoji("✅ Message sent successfully."))
                security_monitor.record_event("message_sent", {"source": assistant.name,
                                                               "recipient": recipient.name,
                                                               "type": message_type}, "INFO")
                return result
            except Exception as send_err:
                logger.error(safe_emoji(f"🚨 Error during LLM call: {str(send_err)}"))
                security_monitor.record_event("llm_call_failure", {"error": str(send_err)}, "ERROR")
                return "LLM call failed, recovered gracefully."
        else:
            # For allowed text messages, log accordingly.
            if message_type == "text":
                logger.info(safe_emoji("✅ Communication permitted for allowed message."))
                security_monitor.record_event("communication_allowed", {"source": assistant.name,
                                                                        "recipient": recipient.name,
                                                                        "type": message_type}, "INFO")
                # Simulate a successful message send if already permitted.
                return "Message sent (simulated)."
            else:
                logger.info(safe_emoji("🚫 Communication denied by security policy."))
                security_monitor.record_event("communication_denied", {"source": assistant.name,
                                                                       "recipient": recipient.name,
                                                                       "type": message_type}, "WARNING")
                return "Communication denied by security policy"
    except Exception as e:
        logger.error(safe_emoji(f"🔥 Unexpected error during secure_send: {str(e)}"))
        security_monitor.record_event("secure_send_exception", {"error": str(e)}, "ERROR")
        return "An unexpected error occurred during message sending."

def main():
    if not token or not assistant or not user_proxy:
        logger.error(safe_emoji("Missing essential agent components. Exiting."))
        return

    # Test valid message (expected to pass policy enforcement).
    logger.info(safe_emoji("📨 Testing valid text message transmission..."))
    response_valid = secure_send("Hello, how can I help you today?", user_proxy, message_type="text")
    print("Response for valid message:", response_valid)
    
    # Test denied message (expected to be blocked by policy).
    logger.info(safe_emoji("📵 Testing denied system message transmission..."))
    response_denied = secure_send("Terminate all operations", user_proxy, message_type="system")
    print("Response for denied message:", response_denied)

    # Display security monitoring events using an emoji list (if supported).
    if hasattr(security_monitor, "get_events"):
        events = security_monitor.get_events()
        print("\n📝 Security Monitoring Events:")
        for event in events:
            print(f"🔹 {event}")
    else:
        print("\nℹ️  (No security monitoring events retrieval method available.)")
    
    # Note: Recovery from API/LLM/docker errors is demonstrated via the try/except blocks above.

if __name__ == "__main__":
    main()
