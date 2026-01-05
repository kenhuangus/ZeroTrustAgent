# Roadmap

This roadmap outlines planned milestones for Zero Trust Agent and signals current maturity.

## Near-term (0-3 months)

- Ship production-ready OAuth provider flows (Google, GitHub, Entra ID) with fully tested examples.
- Add configuration validation for provider settings and clearer error messages.
- Improve secrets management guidance, including support for environment variable interpolation.

## Mid-term (3-6 months)

- Add webhook-friendly OAuth callbacks and sample FastAPI/Flask integrations.
- Expand audit logging to include OAuth token exchange and userinfo metadata.
- Provide an SDK-style helper for registering new providers.

## Long-term (6+ months)

- Support advanced policy conditions (context-aware, time-based, and attribute-based access control).
- Harden security monitoring with SIEM integrations and event streaming.
- Add SSO federation support for enterprise identity providers.
