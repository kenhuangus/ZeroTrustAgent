"""
Credential Store for Zero Trust Security Agent
"""

from datetime import datetime
from typing import Optional, Dict
from sqlalchemy.exc import SQLAlchemyError
from .models.base import get_session, init_db
from .models.credentials import Credential

class CredentialStore:
    def __init__(self):
        """Initialize the credential store and ensure database is set up"""
        self.engine = init_db()

    def store_credentials(self, identity: str, password_hash: str) -> bool:
        """
        Store new credentials or update existing ones
        
        Args:
            identity: The identity of the user/entity
            password_hash: The hashed password
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            session = get_session()
            credential = session.query(Credential).filter_by(identity=identity).first()
            
            if credential:
                credential.password_hash = password_hash
                credential.updated_at = datetime.utcnow()
            else:
                credential = Credential(
                    identity=identity,
                    password_hash=password_hash
                )
                session.add(credential)
            
            session.commit()
            return True
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()

    def get_credentials(self, identity: str) -> Optional[Dict]:
        """
        Retrieve stored credentials for the given identity
        
        Args:
            identity: The identity to look up
            
        Returns:
            Optional[Dict]: Credential information if found, None otherwise
        """
        try:
            session = get_session()
            credential = session.query(Credential).filter_by(identity=identity).first()
            
            if not credential or not credential.is_active:
                return None
                
            return {
                "identity": credential.identity,
                "password_hash": credential.password_hash,
                "failed_attempts": credential.failed_attempts,
                "last_failed_attempt": credential.last_failed_attempt,
                "is_locked": credential.is_locked
            }
        except SQLAlchemyError:
            return None
        finally:
            session.close()

    def update_failed_attempts(self, identity: str, attempts: int, 
                             is_locked: bool = False) -> bool:
        """
        Update the failed attempts counter for an identity
        
        Args:
            identity: The identity to update
            attempts: Number of failed attempts
            is_locked: Whether to lock the account
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            session = get_session()
            credential = session.query(Credential).filter_by(identity=identity).first()
            
            if credential:
                credential.failed_attempts = attempts
                credential.last_failed_attempt = datetime.utcnow()
                credential.is_locked = is_locked
                session.commit()
                return True
            return False
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()

    def reset_failed_attempts(self, identity: str) -> bool:
        """
        Reset failed attempts counter for an identity
        
        Args:
            identity: The identity to reset
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_failed_attempts(identity, 0, False)

    def delete_credentials(self, identity: str) -> bool:
        """
        Delete credentials for the given identity
        
        Args:
            identity: The identity to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            session = get_session()
            credential = session.query(Credential).filter_by(identity=identity).first()
            
            if credential:
                session.delete(credential)
                session.commit()
                return True
            return False
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()

    def deactivate_credentials(self, identity: str) -> bool:
        """
        Deactivate credentials for the given identity
        
        Args:
            identity: The identity to deactivate
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            session = get_session()
            credential = session.query(Credential).filter_by(identity=identity).first()
            
            if credential:
                credential.is_active = False
                session.commit()
                return True
            return False
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()
