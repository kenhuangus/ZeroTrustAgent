"""
AutoGen Integration Test for Zero Trust Security Agent
"""

import logging
import sys
from dotenv import load_dotenv
from zta_agent import initialize_agent

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def test_autogen_integration():
    """Test AutoGen integration with Zero Trust Security Agent."""
    try:
        # Initialize ZTA components
        logger.info("Initializing Zero Trust Security Agent...")
        zta_components = initialize_agent()
        auth_manager = zta_components['auth_manager']
        autogen_adapter = zta_components['autogen_adapter']
        zta_components['security_monitor']

        # Get authentication token
        logger.info("Authenticating test agent...")
        credentials = {
            "identity": "assistant",
            "secret": "test_secret"
        }
        token = auth_manager.authenticate(credentials)

        if not token:
            logger.error("Authentication failed")
            return False

        logger.info("Authentication successful")

        # Test different message types
        test_messages = [
            {
                "type": "text",
                "content": "Hello, let's solve a problem",
                "expected_result": True
            },
            {
                "type": "function_call",
                "content": {"name": "calculate", "args": {"x": 1, "y": 2}},
                "expected_result": True
            },
            {
                "type": "system",
                "content": "Terminate execution",
                "expected_result": False
            }
        ]

        success_count = 0
        total_tests = len(test_messages)

        for msg in test_messages:
            logger.info(f"Testing message type: {msg['type']}")
            result = autogen_adapter.validate_agent_communication(
                source_agent="assistant",
                target_agent="user",
                message=msg,
                token=token
            )

            if result == msg["expected_result"]:
                success_count += 1
                logger.info(f"Test passed for message type: {msg['type']}")
            else:
                logger.warning(
                    f"Test failed for message type: {msg['type']}, "
                    f"expected {msg['expected_result']}, got {result}"
                )

        # Test message exchange functionality
        logger.info("Testing secure message exchange...")
        exchange_result = autogen_adapter.secure_message_exchange(
            message={"type": "text", "content": "Test message"},
            sender_id="assistant",
            receiver_id="user",
            token=token
        )

        if exchange_result:
            success_count += 1
            logger.info("Message exchange test passed")
        else:
            logger.warning("Message exchange test failed")

        total_tests += 1
        success_rate = (success_count / total_tests) * 100
        logger.info(f"Test completion rate: {success_rate:.1f}% ({success_count}/{total_tests} tests passed)")

        return success_rate == 100

    except Exception as e:
        logger.error(f"Error during AutoGen integration test: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    success = test_autogen_integration()
    if success:
        logger.info("All AutoGen integration tests passed successfully")
        sys.exit(0)
    else:
        logger.error("Some AutoGen integration tests failed")
        sys.exit(1)