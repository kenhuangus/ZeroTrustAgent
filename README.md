pip install zta-agent
```

## Configuration

### 1. Environment Setup

Create a `.env` file from the template:

```bash
cp .env.example .env
```

Required environment variables:
```
TOGETHER_API_KEY=your_api_key_here  # Get from together.ai
```

### 2. Policy Configuration

Create `config/policy.yaml`:

```yaml
auth:
  token_expiry: 3600  # Token expiry in seconds
  secret_key: "your-secret-key-here"

logging:
  level: DEBUG
  file: logs/security.log

policies:
  policies:
    - name: "allow_research_agents"
      conditions:
        agent_id: {"regex": "^research_.*"}
        action_type: {"in": ["execute_task", "research"]}
      effect: "allow"
      priority: 90

    - name: "deny_system_messages"
      conditions:
        action_type: "send_message"
        message.type: {"regex": "^system$"}
      effect: "deny"
      priority: 200
```

## Usage

### Basic Usage

```python
from zta_agent import initialize_agent

# Initialize components
zta_components = initialize_agent()
auth_manager = zta_components['auth_manager']
policy_engine = zta_components['policy_engine']
security_monitor = zta_components['security_monitor']

# Authenticate an agent
token = auth_manager.authenticate({
    "identity": "test_agent",
    "secret": "test_secret"
})

# Record security events
security_monitor.record_event(
    "authentication_success",
    {"agent_id": "test_agent"},
    "INFO"
)
```

### CrewAI Integration with Together AI

```python
from zta_agent import initialize_agent
from crewai import Agent, Task, Crew
from litellm import completion

# Initialize components
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']
auth_manager = zta_components['auth_manager']

# Authenticate agent
token = auth_manager.authenticate({
    "identity": "research_agent",
    "secret": "your_secret"
})

# Create secure agent with Together AI
agent = create_secure_agent("research_agent", token)

# Create and execute tasks
task = create_secure_task(
    "Research AI security best practices",
    agent,
    "research_agent",
    token
)

crew = Crew(
    agents=[agent],
    tasks=[task],
    process=Process.sequential
)
result = crew.kickoff()
```

### AutoGen Integration

```python
from zta_agent import initialize_agent

# Initialize components
zta_components = initialize_agent()
autogen_adapter = zta_components['autogen_adapter']

# Validate communication
result = autogen_adapter.validate_agent_communication(
    source_agent="assistant",
    target_agent="user",
    message={"type": "text", "content": "Hello"},
    token=token
)
```

## Security Considerations

1. **API Key Management**: 
   - Store API keys securely in environment variables
   - Never commit API keys to version control
   - Rotate keys regularly

2. **Policy Configuration**:
   - Start with restrictive policies
   - Use the principle of least privilege
   - Regularly audit policy configurations

3. **Monitoring**:
   - Enable logging for all security events
   - Set up alerts for suspicious activities
   - Regularly review security logs

## API Documentation

### Authentication Manager

```python
auth_manager.authenticate(credentials: Dict) -> str
auth_manager.validate_token(token: str) -> Optional[Dict]
auth_manager.revoke_token(token: str) -> bool
```

### Policy Engine

```python
policy_engine.evaluate(context: Dict) -> bool
policy_engine.add_policy(policy: Policy) -> None
policy_engine.remove_policy(policy_name: str) -> bool
```

### Security Monitor

```python
security_monitor.record_event(event_type: str, details: Dict, severity: str) -> None
security_monitor.get_events(event_type: str = None, severity: str = None) -> List[SecurityEvent]
security_monitor.get_alerts(severity: str = None) -> List[SecurityEvent]