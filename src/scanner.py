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
    Skanuje rekursywnie, raportuje postęp przez kolejkę.
    Zwraca słownik zawierający listę zainfekowanych plików,
    ostrzeżenia, błędy ORAZ listę wszystkich przeskanowanych plików.
    """
    scan_result = {"infected": [], "warnings": [], "error": None, "scanned_files": []} # Dodano scanned_files

    if not mount_point or not os.path.exists(mount_point):
        scan_result["error"] = "Mount point not found or invalid."
        if progress_queue: progress_queue.put(scan_result)
        return scan_result

    clamscan_path = "/opt/homebrew/bin/clamscan"
    if not os.path.exists(clamscan_path):
        clamscan_path = "/usr/local/bin/clamscan"
        if not os.path.exists(clamscan_path):
            scan_result["error"] = "ClamAV executable not found."
            if progress_queue: progress_queue.put(scan_result)
            return scan_result

    # --- Etap 1: Liczenie i zbieranie listy plików ---
    if progress_queue:
        progress_queue.put({"status": "Przygotowywanie... Liczenie plików..."})
    log.info(f"Rozpoczynanie zbierania listy plików dla {mount_point}...")
    try:
        # Od razu zbieramy pełne ścieżki
        files_to_scan_paths = [os.path.join(root, name) for root, _, files in os.walk(mount_point) for name in files]
        scan_result["scanned_files"] = files_to_scan_paths # Zapisujemy listę do wyniku
        total_files = len(files_to_scan_paths)
        log.info(f"Zebrano listę {total_files} plików do przeskanowania.")
    except Exception as e:
        log.error(f"Błąd podczas listowania plików w {mount_point}: {e}", exc_info=True)
        scan_result["error"] = f"Błąd listowania plików: {e}"
        if progress_queue: progress_queue.put(scan_result)
        return scan_result


    if total_files == 0:
        if progress_queue:
             # Zwracamy pełny wynik, nawet jeśli pusty
            progress_queue.put({"progress": 1.0, "status": "Brak plików do skanowania.", "etr": "", "done": True, "result": scan_result})
        log.info("Brak plików do skanowania.")
        return scan_result # Zwracamy pusty, ale poprawny słownik wyniku

    # --- Etap 2: Skanowanie ---
    scanned_count = 0
    start_time = time.time()
    final_return_code = -1
    stderr_output = ""

    try:
        command = [clamscan_path, "-r", "-v", mount_point]
        log.info(f"Uruchamianie polecenia: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', bufsize=1)

        infected_pattern = re.compile(r"^(.*): (.*) FOUND$")
        scanning_pattern = re.compile(r"^Scanning (.*)$")

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: continue

            infected_match = infected_pattern.match(line)
            scanning_match = scanning_pattern.match(line)

            if infected_match:
                file_path, signature = infected_match.groups()
                log.warning(f"Zainfekowany plik: {file_path} (Sygnatura: {signature})")
                if not any(d['path'] == file_path for d in scan_result["infected"]):
                   scan_result["infected"].append({'path': file_path, 'signature': signature})
            elif scanning_match:
                scanned_count += 1
                current_scanned = min(scanned_count, total_files)
                progress = current_scanned / total_files
                elapsed_time = time.time() - start_time
                avg_time = elapsed_time / current_scanned if current_scanned > 0 else 0
                etr = (total_files - current_scanned) * avg_time

                scanned_file_path = scanning_match.group(1).replace("...", "")
                scanned_file_name = os.path.basename(scanned_file_path)
                status_text = f"Skanowanie ({current_scanned}/{total_files}): {scanned_file_name}"
                etr_text = f"Pozostało ok. {format_time(etr)}"

                if progress_queue:
                    progress_queue.put({"progress": progress, "status": status_text, "etr": etr_text})


        _, stderr_output = process.communicate()
        final_return_code = process.returncode
        log.info(f"Clamscan zakończył działanie z kodem: {final_return_code}")
        if stderr_output:
             stderr_output = stderr_output.strip()
             log.warning(f"Clamscan stderr: {stderr_output}")
             if final_return_code == 2:
                 scan_result["warnings"].append(stderr_output)


        if final_return_code == 0:
            log.info("Skanowanie zakończone, nie znaleziono infekcji.")
        elif final_return_code == 1:
            log.warning(f"Skanowanie zakończone, znaleziono {len(scan_result['infected'])} zainfekowanych plików.")
        elif final_return_code == 2:
            log.warning(f"Skanowanie zakończone z ostrzeżeniami (kod: 2). Znaleziono {len(scan_result['infected'])} infekcji.")
        else:
            error_msg = f"Błąd skanera ClamAV (kod: {final_return_code})."
            if stderr_output: error_msg += f" Szczegóły: {stderr_output}"
            else: error_msg += " Brak dodatkowych informacji w stderr."
            log.error(error_msg)
            scan_result["error"] = error_msg

    except Exception as e:
        log.error(f"Krytyczny błąd podczas skanowania: {e}", exc_info=True)
        scan_result["error"] = f"Krytyczny błąd: {e}"

    if progress_queue:
        progress_queue.put({"done": True, "result": scan_result})
    return scan_result