"""
End-to-end Google OAuth flow using Zero Trust Agent.

Prerequisites:
  1) Create OAuth credentials in Google Cloud Console.
  2) Add an authorized redirect URI (default used below is
     http://localhost:8080/oauth2callback).
  3) Export the environment variables listed in .env.example or set them in your shell.

This script prints the authorization URL, asks for the authorization code,
then exchanges it for tokens and validates the user via the ZTA auth manager.
"""

from __future__ import annotations

import os
import secrets
from typing import Dict

from zta_agent.core.auth import AuthenticationManager


def load_google_config() -> Dict:
    return {
        "auth": {
            "google": {
                "client_id": os.environ["ZTA_GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["ZTA_GOOGLE_CLIENT_SECRET"],
                "redirect_uri": os.environ.get(
                    "ZTA_GOOGLE_REDIRECT_URI",
                    "http://localhost:8080/oauth2callback",
                ),
                "scope": os.environ.get(
                    "ZTA_GOOGLE_SCOPE",
                    "openid email profile",
                ),
            }
        }
    }


def main() -> None:
    config = load_google_config()
    auth_manager = AuthenticationManager(config["auth"])

    google_provider = auth_manager.auth_providers["google"]
    state = secrets.token_hex(16)
    auth_url = google_provider.get_authorization_url(state)

    print("Open this URL in your browser and complete the login:")
    print(auth_url)
    print(
        "\nAfter consent, copy the `code` query parameter from the redirect URL "
        "and paste it here."
    )

    authorization_code = input("Authorization code: ").strip()
    if not authorization_code:
        raise SystemExit("No authorization code provided.")

    auth_result = auth_manager.authenticate(
        {
            "provider": "google",
            "code": authorization_code,
            "ip_address": "127.0.0.1",
            "user_agent": "examples/google_oauth_end_to_end.py",
        }
    )

    if not auth_result:
        raise SystemExit("Authentication failed. Check credentials and scopes.")

    print("\nAuthentication succeeded!")
    print(f"Identity: {auth_result.get('identity')}")
    print(f"Email: {auth_result.get('email')}")
    print(f"Name: {auth_result.get('name')}")
    print("Access token issued by ZTA:")
    print(auth_result.get("access_token"))


if __name__ == "__main__":
    main()
