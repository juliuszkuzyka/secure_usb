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
    logging.info("[INIT] Alert callback set")

def get_bsd_name_for_usb(vendor_id, product_id):
    """Map USB device to BSD Name on macOS using diskutil, with system_profiler as fallback."""
    if system != "Darwin":
        return None

    # Próba 1: Użyj diskutil
    try:
        output = subprocess.check_output(["diskutil", "list"], stderr=subprocess.STDOUT).decode(errors="ignore")
        logging.debug(f"[BSD] diskutil list output:\n{output}")
        disk_pattern = re.compile(r"/dev/(disk\d+)(?:s\d+)?")
        disks = disk_pattern.findall(output)
        for disk in set(disks):
            try:
                info_output = subprocess.check_output(["diskutil", "info", disk], stderr=subprocess.STDOUT).decode(errors="ignore")
                logging.debug(f"[BSD] diskutil info {disk}:\n{info_output}")
                vid_match = re.search(r"Vendor ID\s*:\s*0x(\w+)", info_output, re.IGNORECASE)
                pid_match = re.search(r"Product ID\s*:\s*0x(\w+)", info_output, re.IGNORECASE)
                if vid_match and pid_match:
                    current_vid = f"0x{vid_match.group(1).lower()}"
                    current_pid = f"0x{pid_match.group(1).lower()}"
                    if current_vid == vendor_id.lower() and current_pid == product_id.lower():
                        logging.info(f"[BSD] Found BSD Name: {disk} for {vendor_id}:{product_id} via diskutil")
                        return disk
            except subprocess.CalledProcessError as e:
                logging.debug(f"[BSD] diskutil info {disk} failed: {e}")
                continue
        logging.debug(f"[BSD] No BSD Name for {vendor_id}:{product_id} via diskutil")
    except Exception as e:
        logging.debug(f"[BSD] diskutil error: {e}")

    # Próba 2: Fallback na system_profiler
    try:
        output = subprocess.check_output(["system_profiler", "SPUSBDataType"], stderr=subprocess.STDOUT).decode(errors="ignore")
        logging.debug(f"[BSD] system_profiler output:\n{output}")
        lines = output.splitlines()
        current_device = None
        current_vid = None
        current_pid = None
        indent_level = 0

        for line in lines:
            stripped_line = line.lstrip()
            indent = len(line) - len(stripped_line)
            indent_level = indent // 2
            if stripped_line.endswith(":") and indent_level <= 1:
                current_device = stripped_line[:-1]
                current_vid = None
                current_pid = None
                continue
            vid_match = re.search(r"Vendor ID:\s*(0x\w+)(?:\s*\(.*\))?", stripped_line)
            if vid_match:
                current_vid = vid_match.group(1).lower()
            pid_match = re.search(r"Product ID:\s*(0x\w+)", stripped_line)
            if pid_match:
                current_pid = pid_match.group(1).lower()
            bsd_match = re.search(r"BSD Name:\s*(disk\d+)", stripped_line)
            if bsd_match and current_vid and current_pid:
                bsd_name = bsd_match.group(1)
                if current_vid == vendor_id.lower() and current_pid == product_id.lower():
                    logging.info(f"[BSD] Found BSD Name: {bsd_name} for {vendor_id}:{product_id} via system_profiler")
                    return bsd_name
        logging.debug(f"[BSD] No BSD Name for {vendor_id}:{product_id} via system_profiler")
    except Exception as e:
        logging.debug(f"[BSD] system_profiler error: {e}")

    logging.debug(f"[BSD] No BSD Name found for {vendor_id}:{product_id}")
    return None

def block_device_windows(vendor_id, product_id):
    try:
        import win32com.client
        wmi = win32com.client.GetObject("winmgmts:")
        for usb in wmi.InstancesOf("Win32_USBControllerDevice"):
            dependent = usb.Dependent
            if "VID_" in dependent and "PID_" in dependent:
                vid_pid = dependent.split("VID_")[1]
                dev_vendor_id = f"0x{vid_pid[:4].lower()}"
                dev_product_id = f"0x{vid_pid[9:13].lower()}"
                if dev_vendor_id == vendor_id and dev_product_id == product_id:
                    logging.info(f"[BLOCK] Blocking {vendor_id}:{product_id} on Windows")
                    return True
        logging.warning(f"[BLOCK] Could not block {vendor_id}:{product_id} on Windows")
        return False
    except Exception as e:
        logging.error(f"[BLOCK] Windows block error: {e}")
        return False

def block_device_darwin(vendor_id, product_id, bsd_name):
    if bsd_name:
        try:
            subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True)
            logging.info(f"[BLOCK] Ejected {vendor_id}:{product_id} on macOS")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"[BLOCK] macOS eject error: {e}")
            return False
    logging.warning(f"[BLOCK] No BSD Name for {vendor_id}:{product_id}, cannot eject")
    return False

def block_device_linux(vendor_id, product_id):
    try:
        subprocess.run(["uhubctl", "-l", "1-1", "-a", "0"], check=True, capture_output=True)
        logging.info(f"[BLOCK] Disabled port for {vendor_id}:{product_id} on Linux")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"[BLOCK] Linux block error: {e}")
        return False

def get_connected_devices():
    devices = set()
    logging.debug(f"[DEVICE] Scanning USB devices on {system}")
    known_devices = getattr(get_connected_devices, 'known_devices', set())

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
                    device_id = (vendor_id, product_id)
                    if device_id not in known_devices:
                        logging.info(f"[DEVICE] New device: {vendor_id}:{product_id}")
                        known_devices.add(device_id)
                    devices.add(device_id)
        except Exception as e:
            logging.error(f"[DEVICE] Windows USB error: {e}")

    elif system == "Darwin":
        try:
            import usb.core
            import usb.backend.libusb1
            backend = usb.backend.libusb1.get_backend()
            if backend is None:
                raise usb.core.NoBackendError("No libusb backend")
            devices_list = list(usb.core.find(find_all=True, backend=backend))
            for device in devices_list:
                try:
                    vendor_id = f"0x{device.idVendor:04x}"
                    product_id = f"0x{device.idProduct:04x}"
                    bsd_name = get_bsd_name_for_usb(vendor_id, product_id)
                    device_id = (vendor_id, product_id, bsd_name)
                    if device_id not in known_devices:
                        logging.info(f"[DEVICE] New device: {vendor_id}:{product_id}")
                        known_devices.add(device_id)
                    devices.add(device_id)
                except Exception as e:
                    logging.error(f"[DEVICE] Error processing USB device: {e}")
                    continue
        except (ImportError, usb.core.NoBackendError) as e:
            logging.warning(f"[DEVICE] pyusb failed: {e}")
            try:
                output = subprocess.check_output(["system_profiler", "SPUSBDataType"]).decode()
                matches = re.findall(r"Vendor ID: 0x(\w+).*?Product ID: 0x(\w+)", output, re.DOTALL)
                for vendor_id, product_id in matches:
                    vendor_id = f"0x{vendor_id}"
                    product_id = f"0x{product_id}"
                    bsd_name = get_bsd_name_for_usb(vendor_id, product_id)
                    device_id = (vendor_id, product_id, bsd_name)
                    if device_id not in known_devices:
                        logging.info(f"[DEVICE] New device: {vendor_id}:{product_id}")
                        known_devices.add(device_id)
                    devices.add(device_id)
            except Exception as e:
                logging.error(f"[DEVICE] macOS USB error: {e}")

    elif system == "Linux":
        try:
            import pyudev
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                vendor_id = device.get('ID_VENDOR_ID')
                product_id = device.get('ID_MODEL_ID')
                if vendor_id and product_id:
                    device_id = (f"0x{vendor_id}", f"0x{product_id}")
                    if device_id not in known_devices:
                        logging.info(f"[DEVICE] New device: {vendor_id}:{product_id}")
                        known_devices.add(device_id)
                    devices.add(device_id)
        except Exception as e:
            logging.error(f"[DEVICE] Linux USB error: {e}")

    get_connected_devices.known_devices = known_devices
    logging.debug(f"[DEVICE] Found {len(devices)} devices")
    return devices

def monitor_usb():
    logging.info("[INIT] Starting USB monitoring")
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
                    logging.info(f"[DEVICE] Authorized device: {vendor_id}:{product_id}")
                else:
                    action = "UNAUTHORIZED_CONNECTED"
                    logging.warning(f"[ALERT] Unauthorized device: {vendor_id}:{product_id}")
                    if (vendor_id, product_id) not in _already_alerted:
                        bsd_name = extra[0] if extra else None
                        alert_queue.put((vendor_id, product_id, bsd_name))
                        _already_alerted.add((vendor_id, product_id))
                log_event(timestamp, vendor_id, product_id, action)

            for vendor_id, product_id, *_ in removed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"[DEVICE] Disconnected: {vendor_id}:{product_id}")
                log_event(timestamp, vendor_id, product_id, "DISCONNECTED")
                _already_alerted.discard((vendor_id, product_id))

            previous_devices = current_devices
        except Exception as e:
            logging.error(f"[MONITOR] Error: {e}")
            time.sleep(5)

def stop_monitoring():
    logging.info("[INIT] Stopping USB monitoring")
    stop_event.set()