from sqlalchemy import Column, String, DateTime, Boolean, Integer
from datetime import datetime
from .base import Base

class Credential(Base):
    __tablename__ = 'credentials'

    identity = Column(String, primary_key=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    failed_attempts = Column(Integer, default=0)
    last_failed_attempt = Column(DateTime, nullable=True)
    is_locked = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<Credential(identity={self.identity})>"
