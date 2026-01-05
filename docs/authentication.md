# Authentication Providers

This document describes the authentication providers supported by Zero Trust Agent, how to configure them, and how to supply credentials via environment variables.

## Supported Providers

| Provider | Purpose | Config Key |
| --- | --- | --- |
| Password | Username/password authentication with password policies. | `auth` (default provider) |
| OAuth (generic) | Any OAuth 2.0 provider with standard endpoints. | `auth.oauth` |
| Google OAuth | Google identity platform OAuth 2.0. | `auth.google` |
| GitHub OAuth | GitHub OAuth 2.0. | `auth.github` |
| Microsoft Entra ID | Entra ID (Azure AD) OAuth 2.0. | `auth.entra` |
| Certificate | Client certificate authentication. | `auth.certificate` |

## Configuration Templates

Start from the template in `config/authentication.providers.example.yaml`. Copy the sections you need into `config/policy.yaml` under the `auth:` key and replace the placeholders with real values.

```bash
cp config/authentication.providers.example.yaml config/authentication.providers.local.yaml
```

Then merge the relevant `auth` provider block into `config/policy.yaml`.

## Environment Variable Reference

The example scripts in `examples/` read provider credentials from environment variables so secrets never have to be checked into version control.

### Google OAuth

| Variable | Description | Example |
| --- | --- | --- |
| `ZTA_GOOGLE_CLIENT_ID` | OAuth client ID | `123.apps.googleusercontent.com` |
| `ZTA_GOOGLE_CLIENT_SECRET` | OAuth client secret | `GOCSPX-...` |
| `ZTA_GOOGLE_REDIRECT_URI` | Authorized redirect URI | `http://localhost:8080/oauth2callback` |
| `ZTA_GOOGLE_SCOPE` | OAuth scope list | `openid email profile` |

### Microsoft Entra ID

| Variable | Description | Example |
| --- | --- | --- |
| `ZTA_ENTRA_CLIENT_ID` | Application (client) ID | `00000000-0000-0000-0000-000000000000` |
| `ZTA_ENTRA_CLIENT_SECRET` | Client secret | `...` |
| `ZTA_ENTRA_TENANT_ID` | Directory (tenant) ID | `00000000-0000-0000-0000-000000000000` |
| `ZTA_ENTRA_REDIRECT_URI` | Redirect URI | `http://localhost:8080/auth/entra/callback` |
| `ZTA_ENTRA_SCOPE` | OAuth scope list | `openid profile email User.Read` |

### GitHub OAuth

| Variable | Description | Example |
| --- | --- | --- |
| `ZTA_GITHUB_CLIENT_ID` | OAuth client ID | `Iv1.1234567890abcdef` |
| `ZTA_GITHUB_CLIENT_SECRET` | OAuth client secret | `...` |
| `ZTA_GITHUB_REDIRECT_URI` | Redirect URI | `http://localhost:8080/auth/github/callback` |
| `ZTA_GITHUB_SCOPE` | OAuth scope list | `read:user user:email` |

## Provider Configuration Steps

### Password Authentication

Password auth is enabled by default. Configure password policy settings in `config/policy.yaml`:

```yaml
auth:
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true
    max_age_days: 90
    history_size: 5
```

### Google OAuth

1. Create an OAuth client in Google Cloud Console.
2. Add a redirect URI such as `http://localhost:8080/oauth2callback`.
3. Copy the client ID/secret into `config/policy.yaml` or export environment variables.
4. Run the end-to-end example in `examples/google_oauth_end_to_end.py`.

```yaml
auth:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    redirect_uri: "http://localhost:8080/oauth2callback"
    scope: "openid email profile"
```

### Microsoft Entra ID

1. Register an app in Microsoft Entra ID.
2. Add a redirect URI and grant the `openid`, `profile`, `email`, and `User.Read` scopes.
3. Copy the tenant ID, client ID, and client secret into `config/policy.yaml`.

```yaml
auth:
  entra:
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    tenant_id: "your-tenant-id"
    redirect_uri: "http://localhost:8080/auth/entra/callback"
    scope: "openid email profile User.Read"
```

### Generic OAuth

Use the generic OAuth provider for identity systems with standard OAuth 2.0 endpoints.

```yaml
auth:
  oauth:
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    authorize_url: "https://provider.example.com/oauth/authorize"
    token_url: "https://provider.example.com/oauth/token"
    userinfo_url: "https://provider.example.com/oauth/userinfo"
    redirect_uri: "http://localhost:8080/oauth/callback"
    scope: "openid profile email"
```

### Certificate Authentication

Provide a trusted CA certificate and optional CRL settings.

```yaml
auth:
  certificate:
    ca_cert_path: "/path/to/ca.crt"
    verify_crl: true
    crl_path: "/path/to/crl.pem"
    allowed_subjects:
      - "O=YourOrg"
      - "OU=Agents"
```
