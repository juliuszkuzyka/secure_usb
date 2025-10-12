# src/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler
from config import LOG_FILE

def setup_logger():
    """Initialize the logging system with levels and rotation."""
    try:
        # Utwórz katalog na logi, jeśli nie istnieje
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

        # Ustaw format logów
        log_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Stwórz główny logger dla aplikacji
        logger = logging.getLogger('secure_usb')
        logger.setLevel(logging.DEBUG)  # Zbieraj wszystkie logi od poziomu DEBUG w górę

        # Handler do zapisywania logów INFO i ważniejszych w pliku
        # Plik będzie miał max 5MB i powstaną 3 pliki zapasowe
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
        )
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO) # Zapisuj do pliku tylko od poziomu INFO

        # Handler do wyświetlania logów DEBUG i ważniejszych w konsoli (przydatne przy dewelopmencie)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        console_handler.setLevel(logging.DEBUG)

        # Dodaj handlery do loggera
        if not logger.handlers:
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)

        logger.info("Logger initialized successfully")

    except Exception as e:
        print(f"Failed to initialize logger: {e}")
        raise