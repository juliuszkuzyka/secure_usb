# src/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler
from config import LOG_FILE

def setup_logger():
    """Initialize the logging system with levels and rotation."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

        log_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Główny logger nadal łapie wszystko od poziomu DEBUG
        logger = logging.getLogger('secure_usb')
        # Zapobiegaj dodawaniu handlerów wielokrotnie, jeśli funkcja jest wywołana ponownie
        if logger.hasHandlers():
            logger.handlers.clear()
            
        logger.setLevel(logging.DEBUG)
        logger.propagate = False # Zapobiegaj przekazywaniu logów do nadrzędnego loggera (root)

        # --- ZMIANA: Handler plikowy ZAPISUJE wszystko od DEBUG ---
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
        )
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.DEBUG) # Zapisuj WSZYSTKO (od DEBUG) do pliku
        # --- KONIEC ZMIANY ---

        # --- ZMIANA: Handler konsolowy POKAZUJE tylko od INFO ---
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        console_handler.setLevel(logging.INFO) # Pokazuj w konsoli/GUI tylko INFO i ważniejsze
        # --- KONIEC ZMIANY ---

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        # Dodajemy informację o inicjalizacji PO dodaniu handlerów
        logger.info("Logger initialized successfully (File: DEBUG+, Console: INFO+)")

    except Exception as e:
        # Użyj print, bo logger mógł się nie zainicjować
        print(f"Failed to initialize logger: {e}")
        # Można też spróbować zalogować do root loggera jako ostateczność
        logging.exception("Failed to initialize application logger")
        raise