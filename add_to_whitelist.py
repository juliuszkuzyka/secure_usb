# add_to_whitelist.py

import sys
import logging
from logger import setup_logger
from database import add_to_whitelist

def main():
    """Add a USB device to the whitelist via command-line arguments."""
    setup_logger()  # Initialize logger
    if len(sys.argv) != 3:
        print("Usage: python add_to_whitelist.py <vendor_id> <product_id>")
        print("Example: python add_to_whitelist.py 0x05ac 0x12a8")
        return

    vendor_id = sys.argv[1]
    product_id = sys.argv[2]

    try:
        add_to_whitelist(vendor_id, product_id)
        print(f"Added to whitelist: {vendor_id}:{product_id}")
    except Exception as e:
        logging.error(f"Failed to add to whitelist: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()