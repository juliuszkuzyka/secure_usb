# whitelist_manager.py

from config import AUTHORIZED_DEVICES

def is_device_authorized(vendor_id, product_id):
    return (vendor_id, product_id) in AUTHORIZED_DEVICES
