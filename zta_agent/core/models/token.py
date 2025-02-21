from sqlalchemy import Column, String, DateTime, Boolean
from datetime import datetime
from .base import Base

class Token(Base):
    __tablename__ = 'tokens'

    jti = Column(String, primary_key=True)  # JWT ID
    token_type = Column(String, nullable=False)  # 'access' or 'refresh'
    identity = Column(String, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)

    def __repr__(self):
        return f"<Token(jti={self.jti}, type={self.token_type}, identity={self.identity})>"
