"""
Token Store for Zero Trust Security Agent
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError
from .models.base import get_session
from .models.token import Token

class TokenStore:
    def __init__(self):
        """Initialize the token store"""
        self.session = get_session()

    def store_token(self, jti: str, token_type: str, identity: str, 
                   expires_at: datetime, user_agent: str = None, 
                   ip_address: str = None) -> bool:
        """Store a new token"""
        try:
            token = Token(
                jti=jti,
                token_type=token_type,
                identity=identity,
                expires_at=expires_at,
                user_agent=user_agent,
                ip_address=ip_address
            )
            self.session.add(token)
            self.session.commit()
            return True
        except SQLAlchemyError:
            self.session.rollback()
            return False

    def is_token_valid(self, jti: str) -> bool:
        """Check if a token is valid"""
        try:
            token = self.session.query(Token).filter_by(jti=jti).first()
            if not token:
                return False
            
            return (not token.is_revoked and 
                   token.expires_at > datetime.utcnow())
        except SQLAlchemyError:
            return False

    def revoke_token(self, jti: str) -> bool:
        """Revoke a token"""
        try:
            token = self.session.query(Token).filter_by(jti=jti).first()
            if token:
                token.is_revoked = True
                token.revoked_at = datetime.utcnow()
                self.session.commit()
                return True
            return False
        except SQLAlchemyError:
            self.session.rollback()
            return False

    def revoke_all_user_tokens(self, identity: str, 
                             token_type: Optional[str] = None) -> bool:
        """Revoke all tokens for a user"""
        try:
            query = self.session.query(Token).filter_by(identity=identity)
            if token_type:
                query = query.filter_by(token_type=token_type)
            
            tokens = query.all()
            for token in tokens:
                token.is_revoked = True
                token.revoked_at = datetime.utcnow()
            
            self.session.commit()
            return True
        except SQLAlchemyError:
            self.session.rollback()
            return False

    def cleanup_expired_tokens(self) -> bool:
        """Remove expired tokens from the database"""
        try:
            self.session.query(Token).filter(
                Token.expires_at < datetime.utcnow()
            ).delete()
            self.session.commit()
            return True
        except SQLAlchemyError:
            self.session.rollback()
            return False
