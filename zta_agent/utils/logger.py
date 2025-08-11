"""
Logging utility for Zero Trust Security Agent
"""

import logging
import sys
import os
from typing import Dict
import threading

class SecurityLogger:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                instance = super(SecurityLogger, cls).__new__(cls)
                instance.loggers: Dict[str, logging.Logger] = {}
                cls._instance = instance
            return cls._instance

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger instance."""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            logger.setLevel(logging.INFO)

            # Create console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)

            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)

            # Add handler to logger
            logger.addHandler(console_handler)

            self.loggers[name] = logger

        return self.loggers[name]

def setup_logging(config: Dict) -> None:
    """Setup logging configuration."""
    log_level = getattr(logging, config.get("level", "INFO").upper())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)

    # Add handler to root logger
    root_logger.addHandler(console_handler)

    # Add file handler if specified in config
    if "file" in config:
        try:
            # Create logs directory if it doesn't exist
            log_dir = os.path.dirname(config["file"])
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(config["file"])
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            console_handler.setLevel(logging.WARNING)
            root_logger.warning(f"Failed to setup file logging: {str(e)}")

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return SecurityLogger().get_logger(name)