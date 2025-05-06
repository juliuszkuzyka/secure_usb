import platform
import time
import logging
from datetime import datetime

from database import is_device_whitelisted, log_event

system = platform.system()

def get_connected_devices():
    """Retrieve a set of connected USB devices (vendor_id, product_id)."""
    devices = set()

    if system == "Windows":
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            for usb in wmi.InstancesOf("Win32_USBControllerDevice"):
                try:
                    dependent = usb.Dependent
                    if "VID_" in dependent and "PID_" in dependent:
                        vid_pid = dependent.split("VID_")[1]
                        vendor_id = f"0x{vid_pid[:4].lower()}"
                        product_id = f"0x{vid_pid[9:13].lower()}"
                        devices.add((vendor_id, product_id))
                except Exception as e:
                    logging.debug(f"Error parsing USB device on Windows: {e}")
                    continue
        except Exception as e:
            logging.error(f"Error accessing USB devices on Windows: {e}")

    elif system == "Darwin":  # macOS
        try:
            import subprocess, re
            output = subprocess.check_output(["system_profiler", "SPUSBDataType"]).decode()
            matches = re.findall(r"Vendor ID: 0x(\w+).*?Product ID: 0x(\w+)", output, re.DOTALL)
            for match in matches:
                devices.add((f"0x{match[0]}", f"0x{match[1]}"))
        except Exception as e:
            logging.error(f"Error accessing USB devices on macOS: {e}")

    elif system == "Linux":
        try:
            import pyudev
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                vendor_id = device.get('ID_VENDOR_ID')
                product_id = device.get('ID_MODEL_ID')
                if vendor_id and product_id:
                    devices.add((f"0x{vendor_id}", f"0x{product_id}"))
                else:
                    logging.debug(f"Skipping USB device with missing VID/PID: {device}")
        except Exception as e:
            logging.error(f"Error accessing USB devices on Linux: {e}")

    return devices

def monitor_usb():
    """Continuously monitor USB devices for connections and disconnections."""
    logging.info("[START] Monitoring USB devices...")
    previous_devices = set()  # Start with empty set to detect all devices at first run

    while True:
        time.sleep(2)
        try:
            current_devices = get_connected_devices()

            # Process all devices at first run or new connections
            added = current_devices - previous_devices
            for device in added:
                vendor_id, product_id = device
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if is_device_whitelisted(vendor_id, product_id):
                    action = "AUTHORIZED_CONNECTED"
                else:
                    action = "UNAUTHORIZED_CONNECTED"
                    logging.warning(f"[BLOCKED] Unauthorized device: {vendor_id}:{product_id}")

                logging.info(f"[{action}] {vendor_id}:{product_id}")
                log_event(timestamp, vendor_id, product_id, action)

            # Process disconnections
            removed = previous_devices - current_devices
            for device in removed:
                vendor_id, product_id = device
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"[DISCONNECTED] {vendor_id}:{product_id}")
                log_event(timestamp, vendor_id, product_id, "DISCONNECTED")

            previous_devices = current_devices
        except Exception as e:
            logging.error(f"Error in USB monitoring loop: {e}")
            time.sleep(5)  # Prevent rapid error looping