"""
Password Policy Manager for Zero Trust Security Agent
"""

import re
from typing import Tuple, List
from datetime import datetime, timedelta

class PasswordPolicy:
    def __init__(self, config: dict):
        """Initialize password policy with configuration"""
        self.min_length = config.get('min_length', 12)
        self.require_uppercase = config.get('require_uppercase', True)
        self.require_lowercase = config.get('require_lowercase', True)
        self.require_numbers = config.get('require_numbers', True)
        self.require_special = config.get('require_special', True)
        self.max_age_days = config.get('max_age_days', 90)
        self.history_size = config.get('history_size', 5)
        self.special_chars = config.get('special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?')

    def validate_password(self, password: str, 
                         password_history: List[str] = None) -> Tuple[bool, str]:
        """
        Validate a password against the policy
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long"

        if self.require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"

        if self.require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"

        if self.require_numbers and not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"

        if self.require_special and not any(c in self.special_chars for c in password):
            return False, f"Password must contain at least one special character ({self.special_chars})"

        if password_history and password in password_history:
            return False, "Password cannot be reused from previous passwords"

        return True, ""

    def get_expiration_date(self, from_date: datetime = None) -> datetime:
        """Calculate password expiration date"""
        if from_date is None:
            from_date = datetime.utcnow()
        return from_date + timedelta(days=self.max_age_days)

    def is_password_expired(self, password_change_date: datetime) -> bool:
        """Check if a password is expired"""
        if not self.max_age_days:  # If max_age_days is 0, passwords never expire
            return False
        expiration_date = self.get_expiration_date(password_change_date)
        return datetime.utcnow() > expiration_date

    def get_password_age_days(self, password_change_date: datetime) -> int:
        """Get the age of a password in days"""
        age = datetime.utcnow() - password_change_date
        return age.days
