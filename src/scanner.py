import os
import logging
import platform
import subprocess
import plistlib
import time
import re
import shutil

log = logging.getLogger('secure_usb.scanner')

def get_mount_point(bsd_name_from_usb_monitor):
    """
    Pobiera punkt montowania dla danego urządzenia na macOS.
    Obsługuje zarówno dyski z partycjami, jak i woluminy bezpośrednie (whole disk).
    """
    if platform.system() != "Darwin" or not bsd_name_from_usb_monitor:
        log.warning("Funkcja get_mount_point jest obecnie zaimplementowana tylko dla macOS.")
        return None
    try:
        # Pobieramy strukturę wszystkich dysków
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external"],
            capture_output=True, text=True, check=True
        )
        full_disk_info = plistlib.loads(result.stdout.encode('utf-8'))
        
        # Szukamy pasującego dysku lub partycji
        for disk_data in full_disk_info.get('AllDisksAndPartitions', []):
            
            # Przypadek 1: BSD Name pasuje do głównego dysku (np. disk5)
            if disk_data.get('DeviceIdentifier') == bsd_name_from_usb_monitor:
                # Sprawdź, czy dysk ma punkt montowania bezpośrednio (np. pendrive bez tabeli partycji)
                if disk_data.get('MountPoint') and os.path.exists(disk_data['MountPoint']):
                    return disk_data['MountPoint']
                
                # Jeśli nie, szukaj w partycjach tego dysku (np. disk4 -> disk4s1)
                for partition in disk_data.get('Partitions', []):
                    mount_point = partition.get('MountPoint')
                    if mount_point and os.path.exists(mount_point):
                        return mount_point

            # Przypadek 2: BSD Name pasuje do konkretnej partycji wewnątrz dysku (np. disk4s1)
            # (Gdyby monitor USB zwrócił ID partycji zamiast dysku)
            for partition in disk_data.get('Partitions', []):
                if partition.get('DeviceIdentifier') == bsd_name_from_usb_monitor:
                    mount_point = partition.get('MountPoint')
                    if mount_point and os.path.exists(mount_point):
                        return mount_point
                        
        return None
    except Exception as e:
        log.error(f"Błąd podczas szukania punktu montowania: {e}")
        return None

def get_clamscan_path():
    """
    Automatycznie wykrywa ścieżkę do pliku wykonywalnego clamscan.
    """
    # Najpierw sprawdź w PATH (systemowe, homebrew itp.)
    path = shutil.which("clamscan")
    if path:
        log.debug(f"Znaleziono clamscan w: {path}")
        return path
    
    # Fallback: sprawdź typowe ścieżki, jeśli nie ma w PATH
    common_paths = [
        "/opt/homebrew/bin/clamscan",
        "/usr/local/bin/clamscan",
        "/usr/bin/clamscan"
    ]
    for p in common_paths:
        if os.path.exists(p):
            log.debug(f"Znaleziono clamscan w typowej ścieżce: {p}")
            return p
            
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
    Skanuje rekursywnie, raportuje postęp przez kolejkę w trybie strumieniowym.
    """
    scan_result = {"infected": [], "warnings": [], "error": None, "scanned_files": []}

    if not mount_point or not os.path.exists(mount_point):
        scan_result["error"] = "Mount point not found or invalid."
        if progress_queue: progress_queue.put(scan_result)
        return scan_result

    clamscan_path = get_clamscan_path()
    if not clamscan_path:
        scan_result["error"] = "Nie znaleziono programu ClamAV (clamscan). Upewnij się, że jest zainstalowany."
        if progress_queue: progress_queue.put(scan_result)
        return scan_result

    if progress_queue:
        progress_queue.put({"status": "Starting scanning..."})
    
    log.info(f"Starting scanning for {mount_point} with {clamscan_path}...")

    scanned_count = 0
    final_return_code = -1
    stderr_output = ""

    try:
        command = [clamscan_path, "-r", "-v", mount_point]
        log.info(f"Uruchamianie polecenia: {' '.join(command)}")
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding='utf-8', 
            errors='ignore', 
            bufsize=1
        )

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
                scanned_file_path = scanning_match.group(1).replace("...", "")
                scan_result["scanned_files"].append(scanned_file_path)
                
                scanned_file_name = os.path.basename(scanned_file_path)
                status_text = f"Skanowanie pliku #{scanned_count}: {scanned_file_name}"
                
                if progress_queue:
                    progress_queue.put({"status": status_text})

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