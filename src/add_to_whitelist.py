import sys
import logging
from .logger import setup_logger
from .database import add_to_whitelist

def main():
    setup_logger()
    if len(sys.argv) != 3:
        print("Usage: python add_to_whitelist.py <vendor_id> <product_id>")
        return

    vendor_id = sys.argv[1]
    product_id = sys.argv[2]

    try:
        add_to_whitelist(vendor_id, product_id)
        print(f"Added to whitelist: {vendor_id}:{product_id}")
    except Exception as e:
        logging.error(f"Add to whitelist failed: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
