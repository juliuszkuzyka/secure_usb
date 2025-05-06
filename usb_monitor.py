# usb_monitor.py

import psutil
import time
from whitelist_manager import is_device_authorized
from logger import log_event
from database import add_device

def list_usb_devices():
    devices = []
    for disk in psutil.disk_partitions(all=True):
        if 'removable' in disk.opts:
            devices.append(disk.device)
    return devices

def monitor_usb():
    previous_devices = set(list_usb_devices())

    while True:
        current_devices = set(list_usb_devices())

        # Nowe urządzenia podłączone
        new_devices = current_devices - previous_devices
        for device in new_devices:
            vendor_id = "mock_vid"   # Na razie "mock", później będzie real VID/PID
            product_id = "mock_pid"
            device_name = device

            if is_device_authorized(vendor_id, product_id):
                log_event(f"AUTHORIZED USB Connected: {device_name} ({vendor_id}:{product_id})")
                add_device(vendor_id, product_id, device_name, authorized=1)
            else:
                log_event(f"UNAUTHORIZED USB Connected: {device_name} ({vendor_id}:{product_id})")
                add_device(vendor_id, product_id, device_name, authorized=0)

        # Odłączone urządzenia
        removed_devices = previous_devices - current_devices
        for device in removed_devices:
            log_event(f"USB Disconnected: {device}")

        previous_devices = current_devices
        time.sleep(5)  # sprawdzaj co 5 sekund
