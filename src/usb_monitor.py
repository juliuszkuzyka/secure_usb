# src/usb_monitor.py

import platform
import time
import logging
from datetime import datetime
from .database import is_device_whitelisted, log_event
from threading import Event
import queue
import subprocess
import plistlib

# Importy specyficzne dla macOS
try:
    # Zakładamy, że kod będzie uruchamiany tylko na macOS, więc importujemy bezpośrednio
    import usb.core
    import usb.util
except ImportError as e:
    # Logujemy błąd krytyczny, jeśli brakuje zależności na macOS
    logging.critical(f"Missing critical macOS dependency: {e}. Please install pyusb and libusb (`pip install pyusb`, `brew install libusb`).")
    # Można tutaj rzucić wyjątek lub zakończyć aplikację, jeśli biblioteki są absolutnie wymagane
    # raise SystemExit(f"Missing critical macOS dependency: {e}")
    # Na razie pozwalamy kontynuować, ale funkcje USB nie zadziałają
    pass


system = platform.system()
# Sprawdzenie systemu przy starcie - jeśli nie macOS, logujemy ostrzeżenie
if system != "Darwin":
     logging.warning(f"This application is optimized for macOS (Darwin). Running on {system} may lead to unexpected behavior or errors.")

alert_queue = queue.Queue()
stop_event = Event()
_already_alerted = set()
log = logging.getLogger('secure_usb.monitor')

def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback
    log.info("Alert callback set")

def get_bsd_name_for_usb(product_string_from_pyusb):
    """Znajduje BSD Name dla urządzenia na macOS, z timeoutami."""
    # Usunięto sprawdzanie `system != "Darwin"`, zakładamy macOS
    if not product_string_from_pyusb:
        return None
    try:
        try:
            result = subprocess.run(
                ["diskutil", "list", "-plist", "external", "physical"],
                capture_output=True, text=True, check=True, timeout=5
            )
        except FileNotFoundError:
             log.error("diskutil command not found.")
             return None
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
             log.error(f"diskutil list failed or timed out: {e}")
             return None

        disk_list_plist = plistlib.loads(result.stdout.encode('utf-8'))

        for disk_info in disk_list_plist.get('AllDisksAndPartitions', []):
            bsd_name = disk_info.get('DeviceIdentifier')
            if not bsd_name: continue
            try:
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", bsd_name],
                    capture_output=True, text=True, check=True, timeout=3
                )
                device_info_plist = plistlib.loads(info_result.stdout.encode('utf-8'))
                registry_name = device_info_plist.get('IORegistryEntryName')
                log.debug(f"Checking {bsd_name}: Registry='{registry_name}', Product='{product_string_from_pyusb}'")
                if registry_name and product_string_from_pyusb in registry_name:
                    log.debug(f"BSD Name found: {bsd_name} for '{product_string_from_pyusb}'")
                    return bsd_name
            except (subprocess.CalledProcessError, plistlib.InvalidFileException, subprocess.TimeoutExpired) as e:
                log.debug(f"Could not get info for {bsd_name} or timed out: {e}")
                continue
    except Exception as e:
        log.error(f"Unexpected error in get_bsd_name_for_usb: {e}", exc_info=True)

    log.warning(f"No matching BSD Name found for product '{product_string_from_pyusb}'")
    return None

def get_connected_devices():
    """Pobiera listę podłączonych urządzeń USB (tylko macOS)."""
    devices = set()
    log.debug(f"Scanning USB devices on Darwin")

    # Sprawdzenie, czy moduły USB zostały zaimportowane poprawnie
    if 'usb' not in globals() or not hasattr(usb, 'core'):
         log.error("usb.core not available. Cannot scan USB devices.")
         return devices # Zwróć pusty set

    try:
        for device in usb.core.find(find_all=True):
            vendor_id_str = f"0x{device.idVendor:04x}"
            product_id_str = f"0x{device.idProduct:04x}"
            try:
                _ = device.manufacturer # Szybka próba dostępu
                product_string = None
                try: product_string = usb.util.get_string(device, device.iProduct)
                except Exception: pass
                
                # Na macOS zawsze próbujemy znaleźć BSD name, jeśli jest product string
                bsd_name = get_bsd_name_for_usb(product_string) if product_string else None
                device_tuple = (vendor_id_str, product_id_str, bsd_name)
                devices.add(device_tuple)
                log.debug(f"Device found: {device_tuple}")

            except usb.core.USBError as e:
                log.debug(f"USBError accessing {vendor_id_str}:{product_id_str} (permissions?): {e}")
                devices.add((vendor_id_str, product_id_str, None)) # Dodaj bez BSD
            except Exception as e:
                log.warning(f"Error accessing details {vendor_id_str}:{product_id_str}: {e}")
                devices.add((vendor_id_str, product_id_str, None))
    except usb.core.NoBackendError as e:
        log.error(f"libusb backend not found: {e}")
    except Exception as e:
        log.error(f"General macOS USB scan error: {e}", exc_info=True)

    log.debug(f"Scan finished. Found {len(devices)} unique devices.")
    return devices

def monitor_usb(app_instance):
    """Pętla monitorująca zmiany urządzeń USB (tylko macOS)."""
    log.info("Starting USB monitoring loop")
    previous_devices = set()

    # Skanowanie początkowe
    try:
        previous_devices = get_connected_devices()
        log.info(f"Initial scan found {len(previous_devices)} devices.")
        if app_instance:
             app_instance.after(0, app_instance.update_device_list_from_monitor, previous_devices.copy())
        for vendor_id, product_id, bsd_name in previous_devices:
             status = "whitelisted" if is_device_whitelisted(vendor_id, product_id) else "not whitelisted"
             log.info(f"  - Initial device: {vendor_id}:{product_id} (BSD: {bsd_name}, Status: {status})")
             if status == "not whitelisted":
                  if (vendor_id, product_id) not in _already_alerted:
                      alert_queue.put((vendor_id, product_id, bsd_name))
                      _already_alerted.add((vendor_id, product_id))
    except Exception as e:
        log.error(f"Error during initial USB scan: {e}", exc_info=True)

    # Główna pętla monitorowania
    while not stop_event.is_set():
        try:
            stop_event.wait(3)
            if stop_event.is_set(): break

            current_devices = get_connected_devices()

            if current_devices != previous_devices:
                log.debug("Device change detected. Updating lists...")
                added = current_devices - previous_devices
                removed = previous_devices - current_devices

                if app_instance:
                     app_instance.after(0, app_instance.update_device_list_from_monitor, current_devices.copy())

                for vendor_id, product_id, bsd_name in added:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if is_device_whitelisted(vendor_id, product_id):
                        action = "AUTHORIZED_CONNECTED"
                        log.info(f"Authorized device connected: {vendor_id}:{product_id} (BSD: {bsd_name})")
                    else:
                        action = "UNAUTHORIZED_CONNECTED"
                        log.warning(f"Unauthorized device connected: {vendor_id}:{product_id} (BSD: {bsd_name})")
                        if (vendor_id, product_id) not in _already_alerted:
                            alert_queue.put((vendor_id, product_id, bsd_name))
                            _already_alerted.add((vendor_id, product_id))
                    log_event(timestamp, vendor_id, product_id, action)

                for vendor_id, product_id, bsd_name in removed:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    action = "DISCONNECTED"
                    log.info(f"Device disconnected: {vendor_id}:{product_id} (BSD: {bsd_name})")
                    log_event(timestamp, vendor_id, product_id, action)
                    _already_alerted.discard((vendor_id, product_id))

                previous_devices = current_devices
            else:
                 log.debug("No device changes detected.")

        except Exception as e:
            log.error(f"Error in USB monitoring loop: {e}", exc_info=True)
            stop_event.wait(10)

    log.info("USB monitoring loop stopped.")


def block_device_darwin(vendor_id, product_id, bsd_name):
    """Próbuje wysunąć urządzenie na macOS."""
    # Ta funkcja jest specyficzna dla macOS, więc zostaje bez zmian
    if not bsd_name: log.warning(f"No BSD Name for {vendor_id}:{product_id}, cannot eject."); return False
    try:
        subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True, timeout=10)
        log.info(f"Ejected {vendor_id}:{product_id} ({bsd_name})"); return True
    except subprocess.CalledProcessError as e: log.error(f"Eject failed for {bsd_name}: {e.stderr.decode('utf-8', errors='ignore')}")
    except subprocess.TimeoutExpired: log.error(f"Eject timed out for {bsd_name}.")
    except Exception as e: log.error(f"Unexpected eject error for {bsd_name}: {e}", exc_info=True)
    return False

def stop_monitoring():
    log.info("Stopping USB monitoring...")
    stop_event.set()