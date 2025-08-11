from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

Base = declarative_base()

def get_database_url():
    """Get database URL from environment or use default SQLite path"""
    db_url = os.getenv('ZTA_DATABASE_URL')
    if not db_url:
        # Create the data directory if it doesn't exist
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data')
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, 'zta.db')
        db_url = f'sqlite:///{db_path}'
    return db_url

def init_db():
    """Initialize the database"""
    engine = create_engine(get_database_url())
    Base.metadata.create_all(engine)
    return engine

def get_session():
    """Get a database session"""
    engine = create_engine(get_database_url())
    Session = sessionmaker(bind=engine)
    return Session()
