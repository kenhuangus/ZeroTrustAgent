"""
OAuth Authentication Provider
"""

import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode
from .base import AuthenticationProvider

class OAuthProvider(AuthenticationProvider):
    """OAuth 2.0 authentication provider"""
    
    def __init__(self, config: Dict):
        """
        Initialize OAuth provider with configuration
        
        Config should include:
        - client_id: OAuth client ID
        - client_secret: OAuth client secret
        - authorize_url: Authorization endpoint URL
        - token_url: Token endpoint URL
        - userinfo_url: User info endpoint URL
        - redirect_uri: Callback URL for OAuth flow
        - scope: OAuth scopes (space-separated)
        """
        self.config = config
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.authorize_url = config["authorize_url"]
        self.token_url = config["token_url"]
        self.userinfo_url = config["userinfo_url"]
        self.redirect_uri = config["redirect_uri"]
        self.scope = config.get("scope", "openid profile email")

    def get_authorization_url(self, state: str) -> str:
        """
        Get the authorization URL for initiating OAuth flow
        
        Args:
            state: Random state string for CSRF protection
            
        Returns:
            str: Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state
        }
        return f"{self.authorize_url}?{urlencode(params)}"

    def exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """
        Exchange authorization code for access token
        
        Args:
            code: Authorization code from OAuth provider
            
        Returns:
            Optional[Dict]: Token response if successful
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        
        try:
            response = requests.post(self.token_url, data=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """
        Get user information using access token
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Optional[Dict]: User information if successful
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = requests.get(self.userinfo_url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticate using OAuth credentials
        
        Args:
            credentials: Dictionary containing either:
                - code: Authorization code from OAuth provider
                - access_token: Existing OAuth access token
            
        Returns:
            Optional[Dict]: User information if authentication successful
        """
        if "code" in credentials:
            token_response = self.exchange_code_for_token(credentials["code"])
            if not token_response:
                return None
            access_token = token_response.get("access_token")
        else:
            access_token = credentials.get("access_token")

        if not access_token:
            return None

        user_info = self.get_user_info(access_token)
        if user_info:
            return {
                "identity": user_info.get("sub") or user_info.get("email"),
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "provider": "oauth",
                "access_token": access_token,
                "user_info": user_info
            }
        return None

    def validate_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """
        Validate OAuth credentials format
        
        Args:
            credentials: Dictionary containing either code or access_token
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if "code" not in credentials and "access_token" not in credentials:
            return False, "Either authorization code or access token is required"
        return True, ""
