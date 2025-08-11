"""
Security Logger for Zero Trust Security Agent
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict
import os

class SecurityLogger:
    def __init__(self, config: Dict):
        """Initialize the security logger"""
        log_dir = config.get('log_dir', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # File handler for all security events
        fh = logging.FileHandler(os.path.join(log_dir, 'security.log'))
        fh.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(fh)

    def _format_event(self, event_type: str, details: Dict) -> str:
        """Format event details as JSON string"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            **details
        }
        return json.dumps(event)

    def log_authentication_attempt(self, identity: str, success: bool, 
                                 ip_address: Optional[str] = None,
                                 user_agent: Optional[str] = None) -> None:
        """Log an authentication attempt"""
        details = {
            'identity': identity,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        level = logging.INFO if success else logging.WARNING
        self.logger.log(level, self._format_event('authentication_attempt', details))

    def log_password_change(self, identity: str, success: bool,
                          forced: bool = False) -> None:
        """Log a password change event"""
        details = {
            'identity': identity,
            'success': success,
            'forced': forced
        }
        self.logger.info(self._format_event('password_change', details))

    def log_token_event(self, event_type: str, token_id: str,
                       identity: str, details: Dict = None) -> None:
        """Log a token-related event"""
        event_details = {
            'token_id': token_id,
            'identity': identity,
            **(details or {})
        }
        self.logger.info(self._format_event(f'token_{event_type}', event_details))

    def log_security_event(self, event_type: str, details: Dict,
                         level: int = logging.INFO) -> None:
        """Log a generic security event"""
        self.logger.log(level, self._format_event(event_type, details))
