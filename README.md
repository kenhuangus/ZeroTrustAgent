# Zero Trust Agent (ZTA) Framework for Multi-Agent Collaboration

**`zta-agent`** is a Python package designed to implement a Zero Trust security framework for multi-agent systems. It addresses the critical need for secure and controlled interactions in environments where multiple autonomous agents collaborate. This is particularly relevant for systems built using frameworks like CrewAI and AutoGen.

## Why is Zero Trust Crucial for Multi-Agent Systems?

In multi-agent systems, traditional security models that rely on implicit trust are insufficient. A single compromised or malicious agent can jeopardize the entire system. Zero Trust architecture provides a robust solution by:

*   **Assuming No Implicit Trust:** Every agent interaction is treated as potentially hostile.
*   **Continuous Verification:** Authentication and authorization are required for each request.
*   **Least Privilege Principle:** Agents are granted only the necessary permissions.
*   **Microsegmentation:** Limits the blast radius of security breaches.
*   **Comprehensive Monitoring:** Tracks all agent activity for suspicious behavior.

## Project Description

`zta-agent` provides:

*   **Robust Authentication:** Securely verifies agent identities.
*   **Fine-Grained Policy Enforcement:** Controls agent actions based on predefined policies.
*   **Comprehensive Security Monitoring:** Tracks and audits all security-relevant events.

This enables developers to build secure, reliable, and auditable multi-agent systems.

## How Developers Can Contribute

The `zta-agent` project welcomes contributions from AI engineers and framework developers to enhance its capabilities and integrations.

1.  **Framework Adapters:** Developers can create adapters for new AI frameworks, enabling seamless integration with the ZTA framework. This involves implementing security validation hooks and comprehensive monitoring.
2.  **Code Examples:** Contributions of code examples that demonstrate how to integrate core ZTA frameworks with various agentic frameworks are highly encouraged.

## ZTA Architecture

The ZTA architecture consists of:

1.  **Framework Adapters**: Interface between AI frameworks and security components
2.  **Core Zero Trust Agents**: Handle authentication, authorization, and policy enforcement
3.  **Policy Engine**: Evaluates security policies against agent actions
4.  **Security Monitor**: Tracks and audits all security-relevant events

```mermaid
graph TD
    A[AI Framework: CrewAI, AutoGen] --> B[Framework Adapter]
    B --> C[ZeroTrustAgent]
    C --> D[Policies & Monitoring]
```

## Installation & Setup

```bash
git clone https://github.com/kenhuangus/ZeroTrustAgent.git
cd ZeroTrustAgent
pip install build
python -m build
pip install -e .


```

### Basic Configuration

1.  **Environment Setup**

    ```bash
    cp .env.example .env
    ```

2.  **Configure your API keys in `.env`**:

    ```
    TOGETHER_API_KEY=your_api_key_here  # For LLM support
    OPENAI_API_KEY=your_api_key_here    # Optional, for OpenAI integration
    ```

3.  **Create your policy configuration in `config/policy.yaml`**:

    ```yaml
    auth:
      token_expiry: 3600
      secret_key: "your-secret-key-here"

    policies:
      policies:
        - name: "allow_research_agents"
          conditions:
            agent_id: {"regex": "^research_.*"}
            action_type: {"in": ["execute_task", "research"]}
          effect: "allow"
          priority: 90
    ```
4. **Sample test crewai integration with Zero Truse agent**


```bash

python ./examples/crewai_example.py

```
The following is the sample output

   ![Example Output from runing crewai_example.py ](auto-gen-output.png)



## Framework Integration Guide

### For AI Engineers & Framework Developers

1.  **Core Components** (`zta_agent/core/`):

    *   `AuthenticationManager`: Handles agent identity and token management
    *   `PolicyEngine`: Evaluates security policies
    *   `SecurityMonitor`: Tracks and audits agent activities

2.  **Integration Process**:

    *   Create new adapter in `zta_agent/integrations/`
    *   Implement security validation hooks
    *   Add comprehensive monitoring
    *   Follow existing patterns (see CrewAI/AutoGen examples)

3.  **Security Best Practices**:

    *   Follow Zero Trust principles
    *   Implement proper token validation
    *   Add detailed security event logging
    *   Follow policy enforcement patterns

### Example Framework Integration

Here's how to integrate a new AI framework with ZTA:

```python
from typing import Dict, Optional
from ..core.auth import AuthenticationManager
from ..core.policy import PolicyEngine
from ..core.monitor import SecurityMonitor

class NewFrameworkAdapter:
    def __init__(self, auth_manager: AuthenticationManager,
                 policy_engine: PolicyEngine,
                 security_monitor: SecurityMonitor):
        self.auth_manager = auth_manager
        self.policy_engine = policy_engine
        self.security_monitor = security_monitor

    def validate_agent_action(self, agent_id: str, action: Dict, token: str) -> bool:
        """Validate if an agent can perform a specific action."""
        # 1. Validate authentication token
        claims = self.auth_manager.validate_token(token)
        if not claims:
            self.security_monitor.record_event(
                "unauthorized_access",
                {"agent_id": agent_id, "action": action},
                "WARNING"
            )
            return False

        # 2. Create security context
        context = {
            "agent_id": agent_id,
            "action_type": action.get("type"),
            "resource": action.get("resource"),
            "claims": claims,
            "framework": "your_framework_name"
        }

        # 3. Evaluate against policies
        is_allowed = self.policy_engine.evaluate(context)

        # 4. Log the event
        self.security_monitor.record_event(
            "action_validation",
            {"context": context, "allowed": is_allowed},
            "INFO"
        )

        return is_allowed
```

## Integration Examples

### CrewAI Integration

The Zero Trust Security Agent system now simulates two agents:
- **Allowed Agent**: For example, an agent with identity `research_agent` that meets the policy conditions (matches the regex `^research_.*`).
- **Denied Agent**: For example, an agent with identity `denied_agent` that does not meet any allow conditions and falls to the default deny.

When you run the example below, only the allowed agent will proceed with task execution while the denied agent's execution is halted.

```python
from zta_agent import initialize_agent
from crewai import Agent, Task, Crew
from zta_agent.integrations.crewai_adapter import CrewAIAdapter

# Initialize ZTA components
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']
auth_manager = zta_components['auth_manager']

# Authenticate allowed and denied agents
allowed_token = auth_manager.authenticate({
    "identity": "research_agent",
    "secret": "research_secret"
})
denied_token = auth_manager.authenticate({
    "identity": "denied_agent",
    "secret": "denied_secret"
})

# Validate actions for each agent
allowed_decision = crewai_adapter.validate_agent_action("research_agent",
    {"type": "execute_task", "resource": "operation"}, allowed_token)
denied_decision = crewai_adapter.validate_agent_action("denied_agent",
    {"type": "execute_task", "resource": "operation"}, denied_token)

if allowed_decision:
    print("Allowed agent: execution permitted.")
else:
    print("Allowed agent: execution denied.")

if denied_decision:
    print("Denied agent: execution permitted.")
else:
    print("Denied agent: execution denied. Halting further execution.")

# Create tasks only for the allowed agent.
if allowed_decision:
    # Replace with your actual agent creation logic
    agent = Agent(role='Researcher', goal='Research', backstory='...', allow_delegation=False)
    task = Task(
        description="Research AI security patterns",
        agent=agent
    )
    crew = Crew(
        agents=[agent],
        tasks=[task]
    )
    result = crew.kickoff()
    print("Crew execution result:", result)
```


### AutoGen Integration

```python
from zta_agent import initialize_agent

# Initialize components
zta_components = initialize_agent()
autogen_adapter = zta_components['autogen_adapter']
auth_manager = zta_components['auth_manager']

# Authenticate agent
token = auth_manager.authenticate({
    "identity": "test_agent",
    "secret": "test_secret"
})

# Validate agent communication
result = autogen_adapter.validate_agent_communication(
    source_agent="assistant",
    target_agent="user",
    message={"type": "text", "content": "Hello"},
    token=token
)
```
## Security Considerations

**API Key Management**:

*   Store API keys securely in environment variables.
*   Never commit API keys to version control.
*   Rotate keys regularly.

**Policy Configuration**:

*   Start with restrictive policies.
*   Use the principle of least privilege.
*   Regularly audit policy configurations.

**Monitoring**:

*   Enable logging for all security events.
*   Set up alerts for suspicious activities.
*   Regularly review security logs.

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
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
