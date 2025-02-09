┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│   AI Framework  │────▶│  Framework       │────▶│  Core Security │
│   (CrewAI,     │     │  Adapter         │     │  Components    │
│    AutoGen)    │     │                  │     │                │
└─────────────────┘     └──────────────────┘     └────────────────┘
                                                        │
                                                        ▼
                                               ┌────────────────┐
                                               │  Policies &    │
                                               │  Monitoring    │
                                               └────────────────┘
```

The ZTA architecture consists of:
1. **Framework Adapters**: Interface between AI frameworks and security components
2. **Core Security Components**: Handle authentication, authorization, and policy enforcement
3. **Policy Engine**: Evaluates security policies against agent actions
4. **Security Monitor**: Tracks and audits all security-relevant events

## Installation & Setup

```bash
pip install zta-agent
```

### Basic Configuration

1. Environment Setup
```bash
cp .env.example .env
```

2. Configure your API keys in `.env`:
```
TOGETHER_API_KEY=your_api_key_here  # For LLM support
OPENAI_API_KEY=your_api_key_here    # Optional, for OpenAI integration
```

3. Create your policy configuration in `config/policy.yaml`:
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

## Framework Integration Guide

### For AI Engineers & Framework Developers

1. **Core Components** (`zta_agent/core/`):
   - `AuthenticationManager`: Handles agent identity and token management
   - `PolicyEngine`: Evaluates security policies
   - `SecurityMonitor`: Tracks and audits agent activities

2. **Integration Process**:
   - Create new adapter in `zta_agent/integrations/`
   - Implement security validation hooks
   - Add comprehensive monitoring
   - Follow existing patterns (see CrewAI/AutoGen examples)

3. **Security Best Practices**:
   - Follow Zero Trust principles
   - Implement proper token validation
   - Add detailed security event logging
   - Follow policy enforcement patterns

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

### Integration Examples

#### CrewAI Integration
```python
from zta_agent import initialize_agent
from crewai import Agent, Task, Crew

# Initialize ZTA components
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']
auth_manager = zta_components['auth_manager']

# Authenticate agent
token = auth_manager.authenticate({
    "identity": "research_agent",
    "secret": "your_secret"
})

# Create secure agent
agent = create_secure_agent("research_agent", token)

# Create and execute tasks with security validation
task = Task(
    agent=agent,
    description="Research AI security patterns"
)

crew = Crew(
    agents=[agent],
    tasks=[task]
)

# Execute with security checks
result = crew.kickoff()
```

#### AutoGen Integration
```python
from zta_agent import initialize_agent

# Initialize components
zta_components = initialize_agent()
autogen_adapter = zta_components['autogen_adapter']

# Validate agent communication
result = autogen_adapter.validate_agent_communication(
    source_agent="assistant",
    target_agent="user",
    message={"type": "text", "content": "Hello"},
    token=token
)