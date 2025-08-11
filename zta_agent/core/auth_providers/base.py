"""
Base Authentication Provider Interface
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

class AuthenticationProvider(ABC):
    """Base class for authentication providers"""
    
    @abstractmethod
    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticate a user/agent using the provided credentials
        
        Args:
            credentials: Dictionary containing authentication credentials
            
        Returns:
            Optional[Dict]: User/agent information if authentication successful
        """
        pass

    @abstractmethod
    def validate_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """
        Validate the format and content of credentials
        
        Args:
            credentials: Dictionary containing credentials to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        pass
