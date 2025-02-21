"""
Google OAuth Provider
"""

from typing import Dict, Optional
from ..oauth import OAuthProvider

class GoogleOAuthProvider(OAuthProvider):
    """Google-specific OAuth provider"""
    
    def __init__(self, config: Dict):
        """
        Initialize Google OAuth provider
        
        Args:
            config: Dictionary containing:
                - client_id: Google OAuth client ID
                - client_secret: Google OAuth client secret
                - redirect_uri: Callback URL
                - scope: Optional space-separated scopes
        """
        google_config = {
            **config,
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "scope": config.get("scope", "openid email profile")
        }
        super().__init__(google_config)

    def get_authorization_url(self, state: str) -> str:
        """Get Google authorization URL with additional parameters"""
        url = super().get_authorization_url(state)
        # Add Google-specific parameters
        return f"{url}&access_type=offline&prompt=consent"

    def extract_identity(self, user_info: Dict) -> Optional[Dict]:
        """Extract identity from Google user info response"""
        if not user_info:
            return None
            
        return {
            "identity": user_info.get("sub"),
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "picture": user_info.get("picture"),
            "email_verified": user_info.get("email_verified", False),
            "locale": user_info.get("locale"),
            "provider": "google"
        }
