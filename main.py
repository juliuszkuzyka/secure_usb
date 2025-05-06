# main.py

from logger import setup_logger
from database import create_db
from usb_monitor import monitor_usb

if __name__ == "__main__":
    setup_logger()
    create_db()
    monitor_usb()
