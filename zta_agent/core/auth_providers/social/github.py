"""
GitHub OAuth Provider
"""

from typing import Dict, Optional
import requests
from ..oauth import OAuthProvider

class GitHubOAuthProvider(OAuthProvider):
    """GitHub-specific OAuth provider"""
    
    def __init__(self, config: Dict):
        """
        Initialize GitHub OAuth provider
        
        Args:
            config: Dictionary containing:
                - client_id: GitHub OAuth client ID
                - client_secret: GitHub OAuth client secret
                - redirect_uri: Callback URL
                - scope: Optional space-separated scopes
        """
        github_config = {
            **config,
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scope": config.get("scope", "read:user user:email")
        }
        super().__init__(github_config)

    def exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """Override to handle GitHub's token response format"""
        headers = {"Accept": "application/json"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        
        try:
            response = requests.post(self.token_url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """Get GitHub user info and include email"""
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/json"
        }
        
        try:
            # Get basic user info
            user_response = requests.get(self.userinfo_url, headers=headers)
            user_response.raise_for_status()
            user_info = user_response.json()

            # Get user emails
            emails_response = requests.get(
                "https://api.github.com/user/emails",
                headers=headers
            )
            emails_response.raise_for_status()
            emails = emails_response.json()

            # Add primary email to user info
            primary_email = next(
                (email for email in emails if email.get("primary")),
                None
            )
            if primary_email:
                user_info["email"] = primary_email["email"]
                user_info["email_verified"] = primary_email["verified"]

            return user_info
        except requests.RequestException:
            return None

    def extract_identity(self, user_info: Dict) -> Optional[Dict]:
        """Extract identity from GitHub user info response"""
        if not user_info:
            return None
            
        return {
            "identity": str(user_info.get("id")),
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "login": user_info.get("login"),
            "avatar_url": user_info.get("avatar_url"),
            "html_url": user_info.get("html_url"),
            "company": user_info.get("company"),
            "location": user_info.get("location"),
            "email_verified": user_info.get("email_verified", False),
            "provider": "github"
        }
