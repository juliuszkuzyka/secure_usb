# src/scanner.py

import os
import logging
import platform
import subprocess
import plistlib
import time
import re

log = logging.getLogger('secure_usb.scanner')

def get_mount_point(bsd_name_from_usb_monitor):
    """
    Pobiera punkt montowania dla danego urządzenia na macOS.
    """
    if platform.system() != "Darwin" or not bsd_name_from_usb_monitor:
        log.warning("Funkcja get_mount_point jest obecnie zaimplementowana tylko dla macOS.")
        return None
    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external"],
            capture_output=True, text=True, check=True
        )
        full_disk_info = plistlib.loads(result.stdout.encode('utf-8'))
        for disk_data in full_disk_info.get('AllDisksAndPartitions', []):
            if disk_data.get('DeviceIdentifier') == bsd_name_from_usb_monitor:
                for partition in disk_data.get('Partitions', []):
                    mount_point = partition.get('MountPoint')
                    if mount_point and os.path.exists(mount_point):
                        return mount_point
        return None
    except Exception as e:
        log.error(f"Błąd podczas szukania punktu montowania: {e}")
        return None

def format_time(seconds):
    """Formatuje sekundy do czytelnego formatu (minuty, sekundy)."""
    if seconds < 0: seconds = 0
    if seconds < 60:
        return f"{int(seconds)} s"
    minutes = int(seconds // 60)
    seconds = int(seconds % 60)
    return f"{minutes} min {seconds} s"

def scan_device(mount_point, progress_queue=None):
    """
    Skanuje rekursywnie z odczytem outputu w czasie rzeczywistym.
    Postęp jest raportowany przez bezpieczną kolejkę (queue).
    """
    if not mount_point or not os.path.exists(mount_point):
        progress_queue.put({"error": "Mount point not found"})
        return []

    clamscan_path = "/opt/homebrew/bin/clamscan"
    if not os.path.exists(clamscan_path):
        clamscan_path = "/usr/local/bin/clamscan"
        if not os.path.exists(clamscan_path):
            progress_queue.put({"error": "ClamAV not found"})
            return []

    infected_files = []

    # Etap 1: Zbierz listę plików do policzenia (bez blokowania GUI na długo)
    if progress_queue:
        progress_queue.put({"status": "Przygotowywanie... Liczenie plików..."})

    log.info("Rozpoczynanie zbierania listy plików...")
    files_to_scan = [os.path.join(root, name) for root, _, files in os.walk(mount_point) for name in files]
    total_files = len(files_to_scan)
    log.info(f"Zebrano listę {total_files} plików do przeskanowania.")

    if total_files == 0:
        if progress_queue:
            progress_queue.put({"progress": 1.0, "status": "Brak plików do skanowania.", "etr": ""})
        return []

    # Etap 2: Skanowanie
    scanned_count = 0
    start_time = time.time()
    try:
        command = [clamscan_path, "-r", "-v", mount_point]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', bufsize=1)

        infected_pattern = re.compile(r"^(.*): (.*) FOUND$")

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue

            match = infected_pattern.match(line)
            if match:
                file_path, signature = match.groups()
                log.warning(f"Zainfekowany plik: {file_path} (Sygnatura: {signature})")
                if file_path not in infected_files:
                    infected_files.append(file_path)

            if line.startswith("Scanning "):
                scanned_count += 1
                progress = scanned_count / total_files
                elapsed_time = time.time() - start_time
                avg_time = elapsed_time / scanned_count if scanned_count > 0 else 0
                etr = (total_files - scanned_count) * avg_time
                
                scanned_file_name = os.path.basename(line.replace("Scanning ", "").replace("...", ""))
                status_text = f"Skanowanie ({scanned_count}/{total_files}): {scanned_file_name}"
                etr_text = f"Pozostało ok. {format_time(etr)}"
                
                if progress_queue:
                    # Wrzucamy dane do kolejki zamiast bezpośrednio wołać GUI
                    progress_queue.put({"progress": progress, "status": status_text, "etr": etr_text})

        process.wait()
        if process.returncode not in [0, 1]:
            error_output = process.stderr.read()
            log.error(f"Clamscan zakończył działanie z błędem (kod: {process.returncode}): {error_output}")
            if progress_queue:
                progress_queue.put({"error": "Błąd skanera ClamAV. Sprawdź logi."})

    except Exception as e:
        log.error(f"Krytyczny błąd podczas skanowania: {e}", exc_info=True)
        if progress_queue:
            progress_queue.put({"error": f"Krytyczny błąd: {e}"})

    log.info(f"Skanowanie zakończone. Znaleziono {len(infected_files)} zainfekowanych plików.")
    return infected_files