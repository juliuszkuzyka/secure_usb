# logger.py

import logging
import os
from config import LOG_FILE

def setup_logger():
    """Initialize the logging system."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logger initialized successfully")
    except Exception as e:
        print(f"Failed to initialize logger: {e}")
        raise

def log_event(message):
    """Log a specific event with INFO level."""
    try:
        logging.info(message)
    except Exception as e:
        print(f"Failed to log event: {e}")