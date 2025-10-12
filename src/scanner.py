# src/scanner.py

import os
import logging
import platform
import subprocess
import plistlib

log = logging.getLogger('secure_usb.scanner')

# Lista podejrzanych rozszerzeń plików, można ją rozbudowywać
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh", ".scr",
    ".dll", ".jar", ".pyc", ".msi"
]

def get_mount_point(bsd_name_from_usb_monitor):
    """
    Pobiera punkt montowania dla danego urządzenia na macOS.
    Ta wersja bezpośrednio szuka zamontowanej partycji powiązanej z głównym identyfikatorem BSD.
    """
    if platform.system() != "Darwin" or not bsd_name_from_usb_monitor:
        log.warning("Funkcja get_mount_point jest obecnie zaimplementowana tylko dla macOS.")
        return None

    try:
        # Użyj 'diskutil list -plist external', aby uzyskać pełną strukturę dysków zewnętrznych
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external"],
            capture_output=True, text=True, check=True
        )
        full_disk_info = plistlib.loads(result.stdout.encode('utf-8'))

        # Przeszukaj listę 'AllDisksAndPartitions' w poszukiwaniu naszego urządzenia
        for disk_data in full_disk_info.get('AllDisksAndPartitions', []):
            # Sprawdź, czy znaleźliśmy główny identyfikator dysku (np. 'disk4')
            if disk_data.get('DeviceIdentifier') == bsd_name_from_usb_monitor:
                # Jeśli tak, przeszukaj jego partycje w poszukiwaniu punktu montowania
                for partition in disk_data.get('Partitions', []):
                    mount_point = partition.get('MountPoint')
                    if mount_point and os.path.exists(mount_point):
                        part_id = partition.get('DeviceIdentifier')
                        log.info(f"Znaleziono aktywny punkt montowania '{mount_point}' na partycji '{part_id}' dla urządzenia '{bsd_name_from_usb_monitor}'.")
                        return mount_point
        
        log.warning(f"Nie udało się znaleźć aktywnego punktu montowania dla urządzenia {bsd_name_from_usb_monitor} po analizie 'diskutil list'.")
        return None

    except (subprocess.CalledProcessError, plistlib.InvalidFileException) as e:
        log.error(f"Błąd podczas parsowania wyniku 'diskutil list': {e}")
        return None
    except FileNotFoundError:
        log.error("Nie znaleziono narzędzia 'diskutil'. Upewnij się, że uruchamiasz aplikację na macOS.")
        return None


def scan_device(mount_point):
    """
    Skanuje podaną ścieżkę w poszukiwaniu plików z podejrzanymi rozszerzeniami.
    """
    if not mount_point or not os.path.exists(mount_point):
        log.warning(f"Punkt montowania '{mount_point}' jest nieprawidłowy lub nie istnieje.")
        return []

    suspicious_files = []
    log.info(f"Rozpoczynanie skanowania w: {mount_point}")
    try:
        for root, _, files in os.walk(mount_point):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in SUSPICIOUS_EXTENSIONS:
                    file_path = os.path.join(root, file)
                    suspicious_files.append(file_path)
                    log.warning(f"Znaleziono podejrzany plik: {file_path}")
    except OSError as e:
        log.error(f"Błąd podczas skanowania katalogu {mount_point}: {e}")


    log.info(f"Skanowanie zakończone. Znaleziono {len(suspicious_files)} podejrzanych plików.")
    return suspicious_files