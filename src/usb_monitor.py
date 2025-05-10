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
        logging.debug(f"diskutil list output: {output}")
        disks = output.split("\n\n")
        for disk in disks:
            if f"Vendor: " in disk and f"Product: " in disk:
                vid_match = re.search(r"Vendor: (\w+)", disk)
                pid_match = re.search(r"Product: (\w+)", disk)
                if vid_match and pid_match:
                    disk_vendor_id = f"0x{vid_match.group(1)}"
                    disk_product_id = f"0x{pid_match.group(1)}"
                    if disk_vendor_id.lower() == vendor_id.lower() and disk_product_id.lower() == product_id.lower():
                        bsd_match = re.search(r"/dev/(disk\d+)", disk)
                        if bsd_match:
                            return bsd_match.group(1)
        logging.warning(f"No BSD Name found for {vendor_id}:{product_id}")
        return None
    except Exception as e:
        logging.error(f"Error getting BSD Name with diskutil: {e}")
        return None

def get_connected_devices():
    devices = set()
    logging.info(f"Detecting USB devices on {system}...")

    if system == "Windows":
        try:
            import win32com.client
            logging.info("Accessing WMI for USB devices...")
            wmi = win32com.client.GetObject("winmgmts:")
            for usb in wmi.InstancesOf("Win32_USBControllerDevice"):
                dependent = usb.Dependent
                logging.debug(f"Dependent: {dependent}")
                if "VID_" in dependent and "PID_" in dependent:
                    vid_pid = dependent.split("VID_")[1]
                    vendor_id = f"0x{vid_pid[:4].lower()}"
                    product_id = f"0x{vid_pid[9:13].lower()}"
                    devices.add((vendor_id, product_id))
                    logging.info(f"Found device: {vendor_id}:{product_id}")
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
                logging.info(f"Found device: {vendor_id}:{product_id}, bsd_name: {bsd_name}")
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
                    logging.info(f"Found device: {vendor_id}:{product_id}")
        except Exception as e:
            logging.error(f"Linux USB error: {e}")

    logging.info(f"Total devices found: {len(devices)}")
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