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

def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback
    logging.info("[INIT] Alert callback set")

def get_bsd_name_for_usb(product_string_from_pyusb):
    """
    Map a USB device to its BSD Name on macOS by matching the product string.
    """
    if system != "Darwin" or not product_string_from_pyusb:
        return None

    try:
        # Krok 1: Zdobądź listę wszystkich zewnętrznych, fizycznych dysków w formacie plist
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external", "physical"],
            capture_output=True, text=True, check=True
        )
        disk_list_plist = plistlib.loads(result.stdout.encode('utf-8'))

        # Krok 2: Przejdź przez dyski, aby znaleźć pasujący
        for disk_info in disk_list_plist.get('AllDisksAndPartitions', []):
            bsd_name = disk_info.get('DeviceIdentifier')
            if not bsd_name:
                continue

            try:
                # Krok 3: Dla każdego dysku, zdobądź jego szczegółowe informacje
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", bsd_name],
                    capture_output=True, text=True, check=True
                )
                device_info_plist = plistlib.loads(info_result.stdout.encode('utf-8'))

                # Krok 4: Sprawdź, czy IORegistryEntryName z diskutil zawiera nazwę produktu z pyusb
                registry_name = device_info_plist.get('IORegistryEntryName')
                logging.debug(f"[BSD] Checking {bsd_name}: RegistryName='{registry_name}', PyUSB_Product='{product_string_from_pyusb}'")

                if registry_name and product_string_from_pyusb in registry_name:
                    logging.info(f"[BSD] Found BSD Name: {bsd_name} for product '{product_string_from_pyusb}'")
                    return bsd_name

            except (subprocess.CalledProcessError, plistlib.InvalidFileException) as e:
                logging.error(f"[BSD] Could not get info for {bsd_name}: {e}")
                continue

    except (subprocess.CalledProcessError, plistlib.InvalidFileException) as e:
        logging.error(f"[BSD] Failed to execute diskutil or parse its output: {e}")

    logging.warning(f"[BSD] No BSD Name found for product '{product_string_from_pyusb}'")
    return None


def get_connected_devices():
    devices = set()
    logging.debug(f"[DEVICE] Scanning USB devices on {system}")

    if system == "Darwin":
        try:
            for device in usb.core.find(find_all=True):
                try:
                    vendor_id = f"0x{device.idVendor:04x}"
                    product_id = f"0x{device.idProduct:04x}"
                    
                    # Zdobądź nazwę produktu, to nasz nowy klucz do dopasowania
                    product_string = usb.util.get_string(device, device.iProduct)
                    
                    bsd_name = get_bsd_name_for_usb(product_string)
                    
                    device_tuple = (vendor_id, product_id, bsd_name)
                    devices.add(device_tuple)
                    logging.info(f"[DEVICE] Found: {vendor_id}:{product_id} ('{product_string}') -> {bsd_name}")

                except Exception as e:
                    # Niektóre urządzenia mogą być chronione (np. wbudowane kamery) i zgłaszać błędy
                    logging.warning(f"[DEVICE] Could not process a USB device: {e}")
                    continue
        except usb.core.NoBackendError as e:
            logging.error(f"[DEVICE] libusb backend not found. Please install it (`brew install libusb`). Error: {e}")
        except Exception as e:
            logging.error(f"[DEVICE] An unexpected error occurred while scanning USB devices on macOS: {e}")

    elif system == "Windows":
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            for usb_device in wmi.InstancesOf("Win32_USBControllerDevice"):
                dependent = usb_device.Dependent
                if "VID_" in dependent and "PID_" in dependent:
                    vid_pid = dependent.split("VID_")[1]
                    vendor_id = f"0x{vid_pid[:4].lower()}"
                    product_id = f"0x{vid_pid[9:13].lower()}"
                    devices.add((vendor_id, product_id, None)) # Brak BSD name w Windows
        except Exception as e:
            logging.error(f"[DEVICE] Windows USB error: {e}")

    elif system == "Linux":
        try:
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                vendor_id = device.get('ID_VENDOR_ID')
                product_id = device.get('ID_MODEL_ID')
                if vendor_id and product_id:
                    devices.add((f"0x{vendor_id}", f"0x{product_id}", None)) # Brak BSD name w Linux
        except Exception as e:
            logging.error(f"[DEVICE] Linux USB error: {e}")

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
                bsd_name = extra[0] if extra else None
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if is_device_whitelisted(vendor_id, product_id):
                    action = "AUTHORIZED_CONNECTED"
                    logging.info(f"[DEVICE] Authorized device connected: {vendor_id}:{product_id}")
                else:
                    action = "UNAUTHORIZED_CONNECTED"
                    logging.warning(f"[ALERT] Unauthorized device connected: {vendor_id}:{product_id}")
                    if (vendor_id, product_id) not in _already_alerted:
                        alert_queue.put((vendor_id, product_id, bsd_name))
                        _already_alerted.add((vendor_id, product_id))
                log_event(timestamp, vendor_id, product_id, action)

            for vendor_id, product_id, *_ in removed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"[DEVICE] Device disconnected: {vendor_id}:{product_id}")
                log_event(timestamp, vendor_id, product_id, "DISCONNECTED")
                _already_alerted.discard((vendor_id, product_id))

            previous_devices = current_devices
        except Exception as e:
            logging.error(f"[MONITOR] Error in monitoring loop: {e}", exc_info=True)
            time.sleep(5)

def block_device_darwin(vendor_id, product_id, bsd_name):
    if bsd_name:
        try:
            # Potrzebujemy pełnej ścieżki do polecenia
            device_node = f"/dev/{bsd_name}"
            logging.info(f"[BLOCK] Attempting to eject {device_node} on macOS")
            subprocess.run(["diskutil", "eject", device_node], check=True, capture_output=True)
            logging.info(f"[BLOCK] Successfully ejected {vendor_id}:{product_id} ({bsd_name})")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"[BLOCK] macOS eject command failed for {bsd_name}: {e.stderr.decode('utf-8', errors='ignore')}")
            return False
    logging.warning(f"[BLOCK] No BSD Name for {vendor_id}:{product_id}, cannot eject")
    return False

def block_device_windows(vendor_id, product_id):
    # Ta funkcja nie jest używana w macOS, ale zostawiamy ją dla kompatybilności międzyplatformowej
    return False

def block_device_linux(vendor_id, product_id):
    # Ta funkcja nie jest używana w macOS, ale zostawiamy ją dla kompatybilności międzyplatformowej
    return False

def stop_monitoring():
    logging.info("[INIT] Stopping USB monitoring")
    stop_event.set()