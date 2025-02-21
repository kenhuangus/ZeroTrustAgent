"""
Microsoft Entra ID (Azure AD) OAuth Provider
"""

from typing import Dict, Optional
from ..oauth import OAuthProvider

class EntraIDOAuthProvider(OAuthProvider):
    """Microsoft Entra ID-specific OAuth provider"""
    
    def __init__(self, config: Dict):
        """
        Initialize Microsoft Entra ID OAuth provider
        
        Args:
            config: Dictionary containing:
                - client_id: Application (client) ID
                - client_secret: Client secret
                - tenant_id: Directory (tenant) ID
                - redirect_uri: Callback URL
                - scope: Optional space-separated scopes
        """
        tenant_id = config.pop("tenant_id")
        entra_config = {
            **config,
            "authorize_url": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
            "token_url": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "scope": config.get("scope", "openid email profile User.Read")
        }
        super().__init__(entra_config)

    def get_authorization_url(self, state: str) -> str:
        """Get Microsoft authorization URL with additional parameters"""
        url = super().get_authorization_url(state)
        # Add Microsoft-specific parameters
        return f"{url}&response_mode=query"

    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """Get Microsoft Graph user info with additional profile data"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        try:
            # Get basic user info
            response = self._make_request("GET", self.userinfo_url, headers=headers)
            if not response:
                return None
            user_info = response

            # Get user photo (if available)
            photo_response = self._make_request(
                "GET",
                "https://graph.microsoft.com/v1.0/me/photo/$value",
                headers=headers,
                handle_json=False
            )
            if photo_response:
                user_info["photo"] = photo_response

            return user_info
        except Exception:
            return None

    def extract_identity(self, user_info: Dict) -> Optional[Dict]:
        """Extract identity from Microsoft Graph user info response"""
        if not user_info:
            return None
            
        return {
            "identity": user_info.get("id"),
            "email": user_info.get("mail") or user_info.get("userPrincipalName"),
            "name": user_info.get("displayName"),
            "given_name": user_info.get("givenName"),
            "surname": user_info.get("surname"),
            "job_title": user_info.get("jobTitle"),
            "business_phones": user_info.get("businessPhones", []),
            "office_location": user_info.get("officeLocation"),
            "preferred_language": user_info.get("preferredLanguage"),
            "photo": user_info.get("photo"),
            "provider": "entra"
        }
