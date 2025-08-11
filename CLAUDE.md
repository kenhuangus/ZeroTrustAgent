# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Building and Installation
```bash
# Install package in development mode
pip install -e .

# Using build system
pip install build
python -m build

# Install with development dependencies
pip install -e .[dev]
```

### Testing
```bash
# Run all tests with coverage
pytest

# Run specific test file
pytest tests/test_security_analysis.py

# Run tests with verbose output and coverage report
pytest -v --cov=zta_agent --cov-report=term-missing
```

### Development Setup
```bash
# Copy environment configuration
cp .env.example .env

# Run example integrations
python examples/basic_usage.py
python examples/crewai_example.py
python examples/autogen_example.py

# Test framework integrations
python examples/test_crewai.py
python examples/test_autogen.py
```

## Architecture Overview

### Core Framework Structure
The ZeroTrustAgent follows a layered architecture with these main components:

1. **Core Security Layer** (`zta_agent/core/`)
   - `AuthenticationManager`: JWT-based token management with multiple auth providers (password, OAuth, certificate, social login)
   - `PolicyEngine`: YAML-based policy evaluation system with regex and conditional matching
   - `SecurityMonitor`: Event logging, alerting, and audit trail management
   - `SecurityAnalysis`: LLM-powered threat detection and behavioral analytics

2. **Framework Adapters** (`zta_agent/integrations/`)
   - `CrewAIAdapter`: Validates agent actions before CrewAI task execution
   - `AutoGenAdapter`: Monitors inter-agent communication in AutoGen systems
   - Adapters implement validation hooks that intercept framework operations

3. **Authentication Providers** (`zta_agent/core/auth_providers/`)
   - `PasswordProvider`: Traditional username/password authentication
   - `OAuthProvider`: Generic OAuth 2.0 implementation
   - `CertificateProvider`: X.509 certificate-based authentication
   - Social providers: Google, GitHub, Microsoft Entra ID

4. **Security Analysis Engine** (`zta_agent/core/security_analysis/`)
   - `BehavioralAnalytics`: ML-based anomaly detection using Isolation Forest and LSTM
   - `ThreatHunter`: MITRE ATT&CK integration, IOC feeds, YARA rules
   - `LLMAnalyzer`: Multi-provider LLM analysis (OpenAI, Anthropic, Vertex AI)

### Key Architectural Patterns

**Zero Trust Validation Flow:**
```
Framework Action → Adapter → Authentication → Policy Evaluation → Security Monitoring → Allow/Deny
```

**Authentication Chain:**
```
Credentials → Provider Selection → Token Validation → Claims Extraction → Context Building
```

**Policy Evaluation:**
```
Security Context → Condition Matching → Priority-based Decision → Effect Application
```

### Configuration Management
- Main config: `config/policy.yaml` - Contains auth settings, policies, monitoring rules
- Hunting patterns: `config/hunting_patterns.json` - Threat detection rules
- Environment: `.env` - API keys and sensitive configuration
- Logging: Structured logging with configurable levels and file output

### Integration Points
- **CrewAI**: Intercepts task execution through `validate_agent_action()`
- **AutoGen**: Monitors agent communication through `validate_agent_communication()`
- **LLM Providers**: Unified interface supporting OpenAI, Anthropic, Google Vertex AI
- **Threat Intel**: Pluggable feeds including AlienVault OTX, MISP, custom sources

### Security Event Flow
```
Security Event → Monitor Recording → Behavioral Analysis → Threat Hunting → LLM Analysis → Response Action
```

### Data Models
- `Credentials`: User/agent identity with encrypted password storage
- `Token`: JWT tokens with expiration and revocation support  
- `SecurityEvent`: Structured event logging with severity levels
- `Policy`: Condition-based rules with priority and effects
- `ThreatIndicator`: IOC management with confidence scoring

### Key Dependencies
- **AI/LLM**: OpenAI, Anthropic, Google AI, CrewAI, AutoGen
- **Security**: PyJWT, bcrypt, cryptography, pyOpenSSL
- **ML/Analytics**: scikit-learn, tensorflow, pandas, numpy
- **Threat Intel**: yara-python, pymisp, stix2, taxii2-client

## Development Guidelines

### Adding New Framework Adapters
1. Create adapter in `zta_agent/integrations/`
2. Inherit from base pattern established in existing adapters
3. Implement validation hooks for framework-specific operations
4. Add comprehensive security event logging
5. Follow the validation flow: Auth → Policy → Monitor → Response

### Extending Authentication
1. Add new provider in `zta_agent/core/auth_providers/`
2. Inherit from `BaseAuthProvider`
3. Implement `authenticate()` method
4. Update `AuthenticationManager` to register provider
5. Add configuration section to `policy.yaml`

### Policy Configuration
- Policies are evaluated in priority order (higher numbers first)
- Use regex patterns for flexible matching
- Default deny policy should have priority 0
- Test policies with both allow and deny scenarios