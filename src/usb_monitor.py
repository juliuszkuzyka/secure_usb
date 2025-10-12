import platform
import time
import logging
from datetime import datetime
from .database import is_device_whitelisted, log_event
from threading import Event
import queue
import subprocess
import plistlib

# Importowanie bibliotek specyficznych dla platformy
try:
    if platform.system() == "Darwin":
        import usb.core
        import usb.util
    elif platform.system() == "Windows":
        import win32com.client
    elif platform.system() == "Linux":
        import pyudev
except ImportError as e:
    logging.error(f"Missing dependency for current OS: {e}")


system = platform.system()
alert_queue = queue.Queue()
stop_event = Event()
_already_alerted = set()
log = logging.getLogger('secure_usb.monitor') # Używamy dedykowanego loggera

def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback
    log.info("Alert callback set")

def get_bsd_name_for_usb(product_string_from_pyusb):
    if system != "Darwin" or not product_string_from_pyusb:
        return None
    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external", "physical"],
            capture_output=True, text=True, check=True
        )
        disk_list_plist = plistlib.loads(result.stdout.encode('utf-8'))
        for disk_info in disk_list_plist.get('AllDisksAndPartitions', []):
            bsd_name = disk_info.get('DeviceIdentifier')
            if not bsd_name: continue
            try:
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", bsd_name],
                    capture_output=True, text=True, check=True
                )
                device_info_plist = plistlib.loads(info_result.stdout.encode('utf-8'))
                registry_name = device_info_plist.get('IORegistryEntryName')
                log.debug(f"Checking {bsd_name}: Registry='{registry_name}', Product='{product_string_from_pyusb}'")
                if registry_name and product_string_from_pyusb in registry_name:
                    log.info(f"BSD Name found: {bsd_name} for '{product_string_from_pyusb}'")
                    return bsd_name
            except (subprocess.CalledProcessError, plistlib.InvalidFileException) as e:
                log.error(f"Could not get info for {bsd_name}: {e}")
    except (subprocess.CalledProcessError, plistlib.InvalidFileException) as e:
        log.error(f"Failed to execute diskutil list: {e}")
    log.warning(f"No BSD Name found for product '{product_string_from_pyusb}'")
    return None

def get_connected_devices():
    devices = set()
    log.debug(f"Scanning USB devices on {system}")
    if system == "Darwin":
        try:
            for device in usb.core.find(find_all=True):
                try:
                    vendor_id = f"0x{device.idVendor:04x}"
                    product_id = f"0x{device.idProduct:04x}"
                    product_string = usb.util.get_string(device, device.iProduct)
                    bsd_name = get_bsd_name_for_usb(product_string)
                    device_tuple = (vendor_id, product_id, bsd_name)
                    devices.add(device_tuple)
                    log.debug(f"Device found: {vendor_id}:{product_id} ('{product_string}') -> {bsd_name}")
                except Exception:
                    continue # Ignorujemy urządzenia, których nie da się odczytać
        except usb.core.NoBackendError as e:
            log.error(f"libusb backend not found. Please install it (`brew install libusb`). Error: {e}")
        except Exception as e:
            log.error(f"macOS USB scan error: {e}")
    elif system == "Windows":
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            for usb_device in wmi.InstancesOf("Win32_USBControllerDevice"):
                dependent = usb_device.Dependent
                if "VID_" in dependent and "PID_" in dependent:
                    vid_pid = dependent.split("VID_")[1]
                    vendor_id = f"0x{vid_pid[:4].lower()}"
                    product_id = f"0x{vid_pid[9:13].lower()}"
                    devices.add((vendor_id, product_id, None))
        except Exception as e:
            log.error(f"Windows USB error: {e}")
    elif system == "Linux":
        try:
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                vendor_id = device.get('ID_VENDOR_ID')
                product_id = device.get('ID_MODEL_ID')
                if vendor_id and product_id:
                    devices.add((f"0x{vendor_id}", f"0x{product_id}", None))
        except Exception as e:
            log.error(f"Linux USB error: {e}")
    log.debug(f"Found {len(devices)} devices")
    return devices

def monitor_usb():
    log.info("Starting USB monitoring")
    previous_devices = set()
    while not stop_event.is_set():
        time.sleep(2)
        try:
            current_devices = get_connected_devices()
            added = current_devices - previous_devices
            removed = previous_devices - current_devices
            for vendor_id, product_id, *extra in added:
                bsd_name = extra[0] if extra else None
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if is_device_whitelisted(vendor_id, product_id):
                    action = "AUTHORIZED_CONNECTED"
                    log.info(f"Authorized device connected: {vendor_id}:{product_id}")
                else:
                    action = "UNAUTHORIZED_CONNECTED"
                    log.warning(f"Unauthorized device connected: {vendor_id}:{product_id}")
                    if (vendor_id, product_id) not in _already_alerted:
                        alert_queue.put((vendor_id, product_id, bsd_name))
                        _already_alerted.add((vendor_id, product_id))
                log_event(timestamp, vendor_id, product_id, action)
            for vendor_id, product_id, *_ in removed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.info(f"Device disconnected: {vendor_id}:{product_id}")
                log_event(timestamp, vendor_id, product_id, "DISCONNECTED")
                _already_alerted.discard((vendor_id, product_id))
            previous_devices = current_devices
        except Exception as e:
            log.error(f"Error in monitoring loop: {e}", exc_info=True)
            time.sleep(5)

def block_device_darwin(vendor_id, product_id, bsd_name):
    if bsd_name:
        try:
            device_node = f"/dev/{bsd_name}"
            log.info(f"Attempting to eject {device_node} on macOS")
            subprocess.run(["diskutil", "eject", device_node], check=True, capture_output=True)
            log.info(f"Successfully ejected {vendor_id}:{product_id} ({bsd_name})")
            return True
        except subprocess.CalledProcessError as e:
            log.error(f"macOS eject command failed for {bsd_name}: {e.stderr.decode('utf-8', errors='ignore')}")
            return False
    log.warning(f"No BSD Name for {vendor_id}:{product_id}, cannot eject")
    return False

def stop_monitoring():
    log.info("Stopping USB monitoring")
    stop_event.set()