import platform
import time
import logging
from datetime import datetime
from .database import is_device_whitelisted, log_event
from threading import Event
import queue
import subprocess
import re

system = platform.system()
alert_queue = queue.Queue()
stop_event = Event()
_already_alerted = set()

def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback
    logging.info("Alert callback set")

def get_bsd_name_for_usb(vendor_id, product_id):
    """Map USB device (vendor_id, product_id) to BSD Name using diskutil on macOS."""
    if system != "Darwin":
        return None
    try:
        output = subprocess.check_output(["diskutil", "list"]).decode()
        disks = output.split("\n\n")
        for disk in disks:
            if f"Vendor ID: {vendor_id}" in disk and f"Product ID: {product_id}" in disk:
                match = re.search(r"/dev/(disk\d+)", disk)
                if match:
                    return match.group(1)
        return None
    except Exception as e:
        logging.error(f"Error getting BSD Name with diskutil: {e}")
        return None

def get_connected_devices():
    devices = set()

    if system == "Windows":
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            for usb in wmi.InstancesOf("Win32_USBControllerDevice"):
                dependent = usb.Dependent
                if "VID_" in dependent and "PID_" in dependent:
                    vid_pid = dependent.split("VID_")[1]
                    vendor_id = f"0x{vid_pid[:4].lower()}"
                    product_id = f"0x{vid_pid[9:13].lower()}"
                    devices.add((vendor_id, product_id))
        except Exception as e:
            logging.error(f"Windows USB error: {e}")

    elif system == "Darwin":
        try:
            output = subprocess.check_output(["system_profiler", "SPUSBDataType"]).decode()
            matches = re.findall(r"Vendor ID: 0x(\w+).*?Product ID: 0x(\w+)", output, re.DOTALL)
            for vendor_id, product_id in matches:
                vendor_id = f"0x{vendor_id}"
                product_id = f"0x{product_id}"
                bsd_name = get_bsd_name_for_usb(vendor_id, product_id)
                devices.add((vendor_id, product_id, bsd_name))
        except Exception as e:
            logging.error(f"macOS USB error: {e}")

    elif system == "Linux":
        try:
            import pyudev
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                vendor_id = device.get('ID_VENDOR_ID')
                product_id = device.get('ID_MODEL_ID')
                if vendor_id and product_id:
                    devices.add((f"0x{vendor_id}", f"0x{product_id}"))
        except Exception as e:
            logging.error(f"Linux USB error: {e}")

    return devices

def monitor_usb():
    logging.info("Monitoring USB devices...")
    previous_devices = set()

    while not stop_event.is_set():
        time.sleep(2)
        try:
            current_devices = get_connected_devices()
            added = current_devices - previous_devices
            removed = previous_devices - current_devices

            for vendor_id, product_id, *extra in added:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if is_device_whitelisted(vendor_id, product_id):
                    action = "AUTHORIZED_CONNECTED"
                else:
                    action = "UNAUTHORIZED_CONNECTED"
                    logging.warning(f"Unauthorized device detected: {vendor_id}:{product_id}")
                    if (vendor_id, product_id) not in _already_alerted:
                        alert_queue.put((vendor_id, product_id, extra[0] if extra else None))
                        _already_alerted.add((vendor_id, product_id))
                log_event(timestamp, vendor_id, product_id, action)

            for vendor_id, product_id, *_ in removed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_event(timestamp, vendor_id, product_id, "DISCONNECTED")
                _already_alerted.discard((vendor_id, product_id))

            previous_devices = current_devices
        except Exception as e:
            logging.error(f"USB monitoring error: {e}")
            time.sleep(5)

def stop_monitoring():
    stop_event.set()