# OpenAI Agents SDK Zero Trust Integration

## Overview

The OpenAI Agents SDK Zero Trust Integration provides comprehensive security validation for OpenAI Agents SDK operations, implementing zero trust principles to ensure all agent activities are authenticated, authorized, and monitored.

## Architecture

The integration consists of several key components:

### Core Components

1. **OpenAIAgentAdapter**: Main adapter class that provides security validation
2. **Security Validation Points**: Multiple interception points for different operations
3. **Policy Engine Integration**: Configurable policies for different agent operations
4. **Security Monitoring**: Comprehensive logging and event tracking
5. **Token-based Authentication**: JWT token validation for all operations

### Validation Points

The adapter intercepts and validates:

- **Agent Creation**: Validates agent configuration and creator permissions
- **Tool Execution**: Validates function calls and tool arguments
- **Agent Handoffs**: Validates agent-to-agent communication and control transfer
- **Session Management**: Validates session operations (create, update, destroy)
- **Runner Execution**: Validates user input and execution requests
- **Guardrail Execution**: Validates input validation operations

## Installation and Setup

### Prerequisites

```bash
# Install the ZeroTrustAgent package
pip install -e .

# Install OpenAI Agents SDK (when available)
pip install openai-agents
```

### Configuration

Add OpenAI Agents specific policies to your `config/policy.yaml`:

```yaml
policies:
  policies:
    # Allow specific agent types to be created
    - name: "allow_openai_agent_creation"
      conditions:
        action_type: "create_agent"
        framework: "openai_agents"
        agent_name: {"regex": "^(Research|Customer|Data|Analysis).*"}
      effect: "allow"
      priority: 85

    # Allow specific tools to be executed
    - name: "allow_openai_tool_execution"
      conditions:
        action_type: "execute_tool" 
        framework: "openai_agents"
        tool_name: {"regex": "^(weather|search|calculator|research).*"}
      effect: "allow"
      priority: 80

    # Allow handoffs between specific agent types
    - name: "allow_openai_agent_handoffs"
      conditions:
        action_type: "agent_handoff"
        framework: "openai_agents"
        source_agent: {"regex": "^(research_|customer_|data_).*"}
        target_agent: {"regex": "^(research_|customer_|data_).*"}
      effect: "allow"
      priority: 75
```

## Usage Examples

### Basic Integration

```python
from zta_agent import initialize_agent
from zta_agent.integrations.openai_agent_adapter import OpenAIAgentAdapter

# Initialize ZTA components
zta_components = initialize_agent()
openai_adapter = zta_components['openai_agent_adapter']

# Authenticate an agent
auth_manager = zta_components['auth_manager']
auth_result = auth_manager.authenticate({
    "identity": "research_assistant",
    "secret": "secure_password",
    "ip_address": "127.0.0.1",
    "user_agent": "OpenAI-Agent/1.0"
})

token = auth_result["access_token"]
```

### Secure Agent Creation

```python
# Define agent configuration
agent_config = {
    "name": "ResearchAssistant",
    "instructions": "You are a research assistant specialized in data analysis",
    "tools": [weather_tool, search_tool],
    "handoffs": []
}

# Validate agent creation
is_allowed = openai_adapter.validate_agent_creation(agent_config, token)

if is_allowed:
    # Create the actual agent (using OpenAI Agents SDK)
    from agents import Agent
    agent = Agent(
        name=agent_config["name"],
        instructions=agent_config["instructions"],
        tools=agent_config["tools"]
    )
    print("✅ Agent created successfully")
else:
    print("❌ Agent creation denied by security policy")
```

### Secure Tool Execution

```python
def weather_tool(location: str, agent_id: str = "unknown"):
    """Example weather tool"""
    return f"Weather in {location}: 22°C, Sunny"

# Create secure tool wrapper
secure_weather = openai_adapter.create_secure_function_tool(weather_tool, token)

# Execute tool with security validation
try:
    result = secure_weather(location="San Francisco", agent_id="research_assistant")
    print(f"Tool result: {result}")
except PermissionError as e:
    print(f"Tool execution denied: {e}")
```

### Secure Runner Execution

```python
# Validate runner execution with user input
validation_result = openai_adapter.secure_runner_execution(
    agent_config=agent_config,
    user_input="What's the weather like in New York?",
    session_id="session_123",
    token=token
)

if validation_result["allowed"]:
    # Proceed with actual runner execution
    from agents import Runner
    result = Runner.run_sync(agent, validation_result["user_input"])
    print(f"Execution result: {result}")
else:
    print(f"Execution denied: {validation_result['reason']}")
```

### Secure Agent Handoffs

```python
# Validate agent handoff
handoff_allowed = openai_adapter.validate_agent_handoff(
    source_agent="research_assistant",
    target_agent="data_analyst", 
    handoff_context={"reason": "complex_analysis_required", "priority": "high"},
    token=token
)

if handoff_allowed:
    # Proceed with handoff (using OpenAI Agents SDK)
    print("✅ Handoff authorized")
else:
    print("❌ Handoff denied by security policy")
```

### Session Management

```python
# Create secure session
session_allowed = openai_adapter.validate_session_operation(
    session_id="interactive_session_001",
    operation="create",
    session_data={"type": "interactive", "max_turns": 20},
    token=token
)

if session_allowed:
    # Session created and tracked
    print("✅ Session created successfully")
```

## Security Features

### Input Validation

The adapter performs comprehensive input validation:

- **Malicious Pattern Detection**: Detects common injection attempts
- **Size Limits**: Prevents DoS attacks via oversized inputs  
- **Command Injection Prevention**: Blocks system command execution attempts
- **Script Injection Prevention**: Detects XSS and script injection patterns

### Authentication & Authorization

- **JWT Token Validation**: All operations require valid authentication tokens
- **Policy-based Authorization**: Configurable policies control what operations are allowed
- **Audit Trail**: All security decisions are logged for compliance

### Monitoring & Alerting

- **Security Event Logging**: All operations generate security events
- **Threat Detection**: Suspicious patterns trigger alerts
- **Performance Monitoring**: Track execution times and resource usage

## Security Policies

### Policy Configuration

Policies are defined in YAML format with the following structure:

```yaml
- name: "policy_name"
  conditions:
    action_type: "operation_type"
    framework: "openai_agents"
    # Additional conditions...
  effect: "allow" | "deny"
  priority: 100  # Higher numbers = higher priority
```

### Common Policy Patterns

#### Allow Specific Agent Types
```yaml
- name: "allow_research_agents"
  conditions:
    action_type: "create_agent"
    framework: "openai_agents"
    agent_name: {"regex": "^Research.*"}
  effect: "allow"
  priority: 85
```

#### Block Dangerous Tools
```yaml
- name: "deny_system_tools"
  conditions:
    action_type: "execute_tool"
    framework: "openai_agents"
    tool_name: {"regex": ".*(system|exec|shell).*"}
  effect: "deny"
  priority: 200
```

#### Time-based Restrictions
```yaml
- name: "business_hours_only"
  conditions:
    action_type: "runner_execution"
    framework: "openai_agents"
    # Custom condition handlers can check time
  effect: "allow"
  priority: 90
```

## Error Handling

The adapter provides detailed error information for security violations:

```python
try:
    result = secure_tool(dangerous_input)
except PermissionError as e:
    # Log security violation
    logger.warning(f"Security violation: {e}")
    # Return safe error to user
    return {"error": "Operation not permitted"}
```

## Performance Considerations

- **Caching**: Policy evaluations are cached for performance
- **Async Support**: Designed to work with async OpenAI Agents operations
- **Minimal Overhead**: Security checks add <10ms to operation latency

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check token expiry
   - Verify credentials are properly created
   - Check for token revocation

2. **Policy Denials**
   - Review policy configuration
   - Check policy priority ordering
   - Verify condition matching logic

3. **Tool Execution Failures**
   - Check tool argument validation
   - Verify tool name patterns in policies
   - Review security event logs

### Debug Mode

Enable debug logging to see detailed security decisions:

```python
import logging
logging.getLogger('zta_agent').setLevel(logging.DEBUG)
```

### Security Event Monitoring

Monitor security events for patterns:

```python
# Get recent security events
security_monitor = zta_components['security_monitor']
recent_events = security_monitor.get_recent_events(limit=50)

# Filter for denials
denials = [e for e in recent_events if not e.get('allowed', True)]
print(f"Recent denials: {len(denials)}")
```

## Best Practices

### Security Configuration

1. **Principle of Least Privilege**: Grant minimal necessary permissions
2. **Regular Policy Review**: Audit and update policies regularly
3. **Strong Authentication**: Use complex passwords and short token expiry
4. **Monitoring**: Set up alerts for suspicious patterns

### Development Guidelines

1. **Input Sanitization**: Always validate user inputs
2. **Error Handling**: Don't expose sensitive information in errors
3. **Logging**: Log all security-relevant operations
4. **Testing**: Include security tests in your test suite

### Deployment Considerations

1. **Secret Management**: Use environment variables for secrets
2. **Network Security**: Deploy behind firewalls and load balancers
3. **Monitoring**: Set up centralized logging and monitoring
4. **Updates**: Keep ZTA and OpenAI SDK updated

## Integration with Other Systems

### SIEM Integration

Export security events to SIEM systems:

```python
# Custom event handler for SIEM integration
def siem_event_handler(event):
    # Forward to SIEM system
    siem_client.send_event(event)

security_monitor.add_event_handler(siem_event_handler)
```

### Metrics Collection

Collect security metrics:

```python
# Get security metrics
metrics = openai_adapter.get_security_metrics()
print(f"Operations per minute: {metrics['operations_per_minute']}")
print(f"Denial rate: {metrics['denial_rate']}%")
```

## API Reference

### OpenAIAgentAdapter

#### Methods

- `validate_agent_creation(agent_config, token)` - Validate agent creation
- `validate_tool_execution(tool_name, tool_args, agent_id, token)` - Validate tool execution
- `validate_agent_handoff(source_agent, target_agent, context, token)` - Validate handoffs
- `validate_session_operation(session_id, operation, data, token)` - Validate session ops
- `secure_runner_execution(agent_config, user_input, session_id, token)` - Validate execution
- `create_secure_function_tool(func, token)` - Create secure tool wrapper
- `get_security_context(execution_id)` - Get security context information

#### Security Events

The adapter generates the following security events:

- `agent_creation_attempt` - Agent creation attempts
- `tool_execution_attempt` - Tool execution attempts  
- `agent_handoff_attempt` - Agent handoff attempts
- `session_operation_attempt` - Session operation attempts
- `runner_execution_attempt` - Runner execution attempts
- `unauthorized_*` - Unauthorized access attempts
- `malicious_input_detected` - Malicious input detection
- `suspicious_*` - Suspicious activity detection

## Contributing

To contribute to the OpenAI Agents integration:

1. **Add New Validation Points**: Extend the adapter for new SDK features
2. **Improve Security Checks**: Enhance input validation and threat detection
3. **Add Policy Templates**: Create common policy configurations
4. **Performance Optimization**: Improve security check performance
5. **Documentation**: Update docs for new features

## Support

For support with the OpenAI Agents integration:

1. Check the troubleshooting section
2. Review security event logs
3. Test with debug logging enabled
4. File issues with detailed reproduction steps