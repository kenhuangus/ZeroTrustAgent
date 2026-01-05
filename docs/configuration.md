# Configuration Reference

This document outlines configuration options for the Zero Trust Agent. It focuses on the
`SecurityMonitor` configuration used by `zta_agent/core/security_monitor.py`.

## SecurityMonitor

The security monitor reads a dictionary of settings. Optional features are gated behind
explicit flags and fall back safely when missing.

### Schema

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `geoip_enabled` | `bool` | `true` if `geoip_db_path` is set | Enable GeoIP lookups. |
| `geoip_db_path` | `str \| null` | `null` | Path to the GeoIP database file. |
| `threat_intel_enabled` | `bool` | `true` if `threat_intel_api_key` is set | Enable threat-intel lookups. |
| `threat_intel_api_key` | `str \| null` | `null` | API key for AbuseIPDB. |
| `llm_enabled` | `bool` | `true` if `llm` is set | Enable LLM analysis of suspicious events. |
| `llm` | `object \| null` | `null` | LLM configuration for `LLMAnalyzer`. |
| `alert_thresholds` | `object` | `{}` | Map of event types to alert thresholds. |
| `ip_blacklist` | `list[str]` | `[]` | Blocked IPs or CIDR ranges. |
| `ip_whitelist` | `list[str]` | `[]` | Trusted IPs or CIDR ranges. |
| `rate_limits.auth.window` | `int` | `300` | Sliding window for auth rate limiting (seconds). |
| `rate_limits.auth.max_requests` | `int` | `10` | Max auth requests per window. |
| `rate_limits.api.window` | `int` | `60` | Sliding window for API rate limiting (seconds). |
| `rate_limits.api.max_requests` | `int` | `100` | Max API requests per window. |
| `max_auth_failures` | `int` | `5` | Failures before an IP is flagged as suspicious. |
| `log_dir` | `str` | `logs` | Directory for security logs. |

### Example

```yaml
security_monitor:
  geoip_enabled: true
  geoip_db_path: "/var/lib/geoip/GeoLite2-City.mmdb"
  threat_intel_enabled: true
  threat_intel_api_key: "${ABUSEIPDB_API_KEY}"
  llm_enabled: false
  llm:
    provider: "openai"
    model: "gpt-4"
  alert_thresholds:
    authentication_failure: 10
    api_error: 25
  ip_blacklist:
    - "203.0.113.0/24"
  ip_whitelist:
    - "192.0.2.10"
  rate_limits:
    auth:
      window: 300
      max_requests: 10
    api:
      window: 60
      max_requests: 100
  max_auth_failures: 5
  log_dir: "logs"
```
