from sqlalchemy import Column, String, DateTime, Boolean, Integer, JSON
from datetime import datetime
from .base import Base

class Credential(Base):
    __tablename__ = 'credentials'

    identity = Column(String, primary_key=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    failed_attempts = Column(Integer, default=0)
    last_failed_attempt = Column(DateTime, nullable=True)
    is_locked = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    password_history = Column(JSON, default=list)  # Store last N password hashes
    require_password_change = Column(Boolean, default=False)
    password_expires_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)

    def __repr__(self):
        return f"<Credential(identity={self.identity})>"
