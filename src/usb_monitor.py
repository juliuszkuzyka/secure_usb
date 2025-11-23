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
    import usb.core
    import usb.util
except ImportError as e:
    logging.critical(f"Missing critical macOS dependency: {e}")
    pass

system = platform.system()
alert_queue = queue.Queue()
stop_event = Event()
_already_alerted = set()
log = logging.getLogger('secure_usb.monitor')

# Mapa klas USB
USB_CLASSES = {
    1: "AUDIO",
    2: "NETWORK",
    3: "HID",
    6: "IMAGING",
    8: "STORAGE",    # Pamięć masowa
    9: "HUB",
    10: "DATA",
    11: "SMARTCARD",
    14: "VIDEO",
    224: "WIRELESS",
    254: "APP_SPEC",
    255: "VENDOR"
}

def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback

def get_device_classes(device):
    """Skanuje urządzenie i zwraca listę wykrytych klas."""
    found_classes = set()
    try:
        if device.bDeviceClass in USB_CLASSES:
            found_classes.add(USB_CLASSES[device.bDeviceClass])
        
        for config in device:
            for interface in config:
                if interface.bInterfaceClass in USB_CLASSES:
                    found_classes.add(USB_CLASSES[interface.bInterfaceClass])
    except Exception:
        pass
    return sorted(list(found_classes))

def get_bsd_name_for_usb(product_string):
    """Znajduje BSD Name dla urządzenia pamięci masowej na macOS."""
    if not product_string:
        return None
    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external", "physical"],
            capture_output=True, text=True, check=True, timeout=5
        )
        disk_list_plist = plistlib.loads(result.stdout.encode('utf-8'))

        for disk_info in disk_list_plist.get('AllDisksAndPartitions', []):
            bsd_name = disk_info.get('DeviceIdentifier')
            if not bsd_name:
                continue
            try:
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", bsd_name],
                    capture_output=True, text=True, check=True, timeout=3
                )
                info_plist = plistlib.loads(info_result.stdout.encode('utf-8'))
                registry_name = info_plist.get('IORegistryEntryName', '')
                
                if product_string in registry_name:
                    return bsd_name
            except Exception:
                continue
    except Exception:
        pass
    return None

def get_connected_devices():
    """Zwraca zestaw: (vendor, product, bsd, device_name, classes_tuple)"""
    devices = set()
    if 'usb' not in globals():
        return devices

    try:
        for device in usb.core.find(find_all=True):
            vendor_id_str = f"0x{device.idVendor:04x}"
            product_id_str = f"0x{device.idProduct:04x}"
            bsd_name = None
            device_name = "Unknown Device"
            device_classes = []

            try:
                manufacturer = ""
                product = ""
                if device.iManufacturer:
                    manufacturer = usb.util.get_string(device, device.iManufacturer)
                if device.iProduct:
                    product = usb.util.get_string(device, device.iProduct)
                
                name_parts = [part for part in [manufacturer, product] if part]
                if name_parts:
                    device_name = " ".join(name_parts)

                if product:
                    bsd_name = get_bsd_name_for_usb(product)
                
                device_classes = get_device_classes(device)
                classes_tuple = tuple(device_classes)
                
                devices.add((vendor_id_str, product_id_str, bsd_name, device_name, classes_tuple))

            except Exception:
                devices.add((vendor_id_str, product_id_str, None, "Unknown Device", ()))
    except Exception as e:
        log.error(f"Scan error: {e}")

    return devices

def monitor_usb(app_instance):
    previous_devices = set()
    
    try:
        previous_devices = get_connected_devices()
        if app_instance:
            app_instance.after(0, app_instance.update_device_list_from_monitor, previous_devices.copy())
        
        for vendor_id, product_id, bsd_name, device_name, device_classes in previous_devices:
             if not is_device_whitelisted(vendor_id, product_id):
                  if (vendor_id, product_id) not in _already_alerted:
                      alert_queue.put((vendor_id, product_id, bsd_name, list(device_classes)))
                      _already_alerted.add((vendor_id, product_id))
    except Exception:
        pass

    while not stop_event.is_set():
        try:
            stop_event.wait(3)
            if stop_event.is_set():
                break
                
            current_devices = get_connected_devices()

            if current_devices != previous_devices:
                added_devices = current_devices - previous_devices
                removed_devices = previous_devices - current_devices

                if app_instance:
                    app_instance.after(0, app_instance.update_device_list_from_monitor, current_devices.copy())

                for vendor_id, product_id, bsd_name, device_name, device_classes in added_devices:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    classes_list = list(device_classes)
                    
                    if is_device_whitelisted(vendor_id, product_id):
                        log.info(f"Authorized: {vendor_id}:{product_id} ({device_name})")
                        log_event(timestamp, vendor_id, product_id, "CONNECTED_AUTH")
                    else:
                        action = "CONNECTED_UNAUTH"
                        
                        if "HUB" in classes_list and "HID" in classes_list:
                            action = "CRITICAL_HUB_HID_COMBO"
                        elif "HID" in classes_list:
                            action = "WARNING_HID"
                        elif "STORAGE" in classes_list: # --- NOWE: Logowanie Storage ---
                            action = "WARNING_STORAGE"
                        elif "NETWORK" in classes_list or "WIRELESS" in classes_list:
                            action = "WARNING_NETWORK"
                        elif "AUDIO" in classes_list or "VIDEO" in classes_list:
                            action = "WARNING_SURVEILLANCE"
                        elif "HUB" in classes_list:
                            action = "NOTICE_HUB"
                        
                        log.warning(f"Unauthorized: {vendor_id}:{product_id} ({device_name}) [{action}] Classes: {classes_list}")
                        log_event(timestamp, vendor_id, product_id, action)
                        
                        if (vendor_id, product_id) not in _already_alerted:
                            alert_queue.put((vendor_id, product_id, bsd_name, classes_list))
                            _already_alerted.add((vendor_id, product_id))

                for vendor_id, product_id, bsd_name, device_name, device_classes in removed_devices:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log.info(f"Disconnected: {vendor_id}:{product_id} ({device_name})")
                    log_event(timestamp, vendor_id, product_id, "DISCONNECTED")
                    _already_alerted.discard((vendor_id, product_id))

                previous_devices = current_devices
        except Exception as e:
            log.error(f"Monitor loop error: {e}")
            stop_event.wait(5)