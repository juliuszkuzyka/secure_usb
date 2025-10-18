# src/gui.py

import customtkinter as ctk
import logging
import os
import sqlite3
from threading import Thread
from tkinter import messagebox, END, Text
from datetime import datetime
import csv
import json
import subprocess
import platform
from queue import Queue

# Zakładamy importy tylko dla macOS
try:
    import usb.core
    import usb.util
except ImportError:
    logging.error("Nie znaleziono pyusb lub libusb. Funkcje monitorowania USB mogą nie działać.")

from .usb_monitor import get_connected_devices, monitor_usb, set_alert_callback, alert_queue
from .database import is_device_whitelisted, add_to_whitelist, remove_from_whitelist
from .scanner import scan_device, get_mount_point
from config import LOG_FILE, DB_FILE

log = logging.getLogger('secure_usb.gui')

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        # ... (reszta __init__ bez zmian) ...
        log.info("Starting USBMonitorApp")
        self.title("USB Security Monitor")
        self.geometry("1400x900")
        self.configure(fg_color="#0D1B2A")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.devices = set()
        self.unauthorized_device = None # Nadal używane do alertów
        self.device_checkboxes = {}
        self.whitelist_checkboxes = {}
        self.scan_progress_queue = Queue()
        self.is_scanning = False

        self.setup_ui()
        set_alert_callback(self.process_alert)
        Thread(target=monitor_usb, args=(self,), daemon=True).start()
        self.check_alert_queue()
        self.update_gui_loop()

    def setup_ui(self):
        # ... (bez zmian aż do przycisku eject) ...
        self.main_frame = ctk.CTkFrame(self, fg_color="#0D1B2A", corner_radius=0)
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="#1B263B", corner_radius=10, border_width=1, border_color="#415A77")
        self.header_frame.pack(fill="x", pady=(0, 10))
        self.header_label = ctk.CTkLabel(self.header_frame, text="🔒 USB Security Monitor", font=("Segoe UI", 28, "bold"), text_color="#E0E1DD", anchor="w")
        self.header_label.pack(pady=10, padx=15)
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure((0, 1), weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="#1B263B", corner_radius=10)
        self.left_frame.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="nsew")
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=3)
        self.left_frame.grid_rowconfigure(3, weight=2)
        self.device_label = ctk.CTkLabel(self.left_frame, text="📟 Connected USB Devices", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.device_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")
        self.device_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#2D2D2D", border_color="#415A77", border_width=1, corner_radius=8)
        self.device_list_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.whitelist_label = ctk.CTkLabel(self.left_frame, text="✅ Whitelisted Devices", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.whitelist_label.grid(row=2, column=0, pady=(10, 5), padx=10, sticky="w")
        self.whitelist_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#2D2D2D", border_color="#415A77", border_width=1, corner_radius=8)
        self.whitelist_list_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="#1B263B", corner_radius=10)
        self.right_frame.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)
        self.log_label = ctk.CTkLabel(self.right_frame, text="📜 Application Events (INFO+)", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.log_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")
        self.tabview = ctk.CTkTabview(self.right_frame, fg_color="#2D2D2D", segmented_button_fg_color="#415A77", segmented_button_selected_color="#778DA9", text_color="#E0E1DD")
        self.tabview.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.tabview.add("Logs"); self.tabview.add("Export")
        self.log_text = ctk.CTkTextbox(self.tabview.tab("Logs"), height=400, font=("Consolas", 13), corner_radius=8, fg_color="#2D2D2D", text_color="#D4D4D4", wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5); self.log_text.configure(state="disabled")
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2D2D2D"); self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.export_csv_button = ctk.CTkButton(self.export_frame, text="Export CSV 📄", command=self.export_logs_csv, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 14), corner_radius=8); self.export_csv_button.pack(pady=10)
        self.export_json_button = ctk.CTkButton(self.export_frame, text="Export JSON 📋", command=self.export_logs_json, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 14), corner_radius=8); self.export_json_button.pack(pady=10)
        self.buttons_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A"); self.buttons_frame.pack(fill="x", pady=10)
        self.add_button = ctk.CTkButton(self.buttons_frame, text="Add Selected to Whitelist ➕", command=self.add_selected_to_whitelist, fg_color="#2ECC71", hover_color="#27AE60", font=("Segoe UI", 14), corner_radius=8, width=220); self.add_button.pack(side="left", padx=5)
        self.remove_button = ctk.CTkButton(self.buttons_frame, text="Remove Selected from Whitelist ➖", command=self.remove_selected_from_whitelist_list, fg_color="#E74C3C", hover_color="#C0392B", font=("Segoe UI", 14), corner_radius=8, width=260); self.remove_button.pack(side="left", padx=5)
        self.scan_button = ctk.CTkButton(self.buttons_frame, text="Scan Selected 🔍", command=self.scan_selected_device, fg_color="#F39C12", hover_color="#D35400", font=("Segoe UI", 14), corner_radius=8, width=180); self.scan_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(self.buttons_frame, text="Refresh GUI 🔄", command=self.force_refresh_gui, fg_color="#3498DB", hover_color="#2980B9", font=("Segoe UI", 14), corner_radius=8, width=140); self.refresh_button.pack(side="left", padx=5)
        
        # --- ZMIANA: Tekst przycisku Eject ---
        self.block_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A"); self.block_frame.pack(fill="x", pady=5)
        self.block_button = ctk.CTkButton(self.block_frame, text="Eject Selected Device(s) 🚫", command=self.eject_selected_devices, fg_color="#E74C3C", hover_color="#C0392B", font=("Segoe UI", 14), corner_radius=8, width=300) # Zmieniono komendę i tekst
        # --- KONIEC ZMIANY ---
        self.block_button.pack(pady=5)
        
        self.progress = ctk.CTkProgressBar(self.main_frame, width=700, progress_color="#3498DB", fg_color="#2D2D2D"); self.progress.set(0); self.progress.pack(pady=10)
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A"); self.status_frame.pack(fill="x", pady=5)
        self.status_label = ctk.CTkLabel(self.status_frame, text="Monitoring USB devices... 🔍", font=("Segoe UI", 14), text_color="#A0A0A0", anchor="w"); self.status_label.pack(side="left", padx=10, fill="x", expand=True)
        self.etr_label = ctk.CTkLabel(self.status_frame, text="", font=("Segoe UI", 14), text_color="#A0A0A0", anchor="e"); self.etr_label.pack(side="right", padx=10)
        self.alert_label = ctk.CTkLabel(self.main_frame, text="", font=("Segoe UI", 16, "bold"), text_color="#E74C3C")

    def update_device_list_from_monitor(self, current_devices_set):
         """Bezpieczna aktualizacja listy urządzeń z wątku monitora."""
         if not self.is_scanning:
             self.devices = current_devices_set
             self.redraw_device_list()
         else:
             log.debug("Skipping device list update during scan.")

    def force_refresh_gui(self):
         """Wymusza odświeżenie list i logów."""
         log.info("Manual GUI refresh requested.")
         self.redraw_device_list()
         self.redraw_whitelist_list()
         self.update_log_display()

    def update_gui_loop(self):
        """Pętla odświeżająca GUI (oprócz listy podłączonych urządzeń)."""
        try:
            if self.is_scanning:
                log.debug("Scan in progress, skipping GUI update loop.")
                self.after(5000, self.update_gui_loop)
                return

            self.redraw_whitelist_list()
            self.update_log_display()

        except Exception as e:
            log.error(f"GUI update loop error: {e}", exc_info=True)
        finally:
            self.after(5000, self.update_gui_loop)

    def update_log_display(self):
         """Odczytuje plik logów, filtruje i aktualizuje pole w GUI."""
         if hasattr(self, 'log_text') and self.log_text.winfo_exists():
             try:
                 if os.path.exists(LOG_FILE):
                     with open(LOG_FILE, "r", encoding='utf-8') as f: all_lines = f.readlines()
                     filtered_lines = [line for line in all_lines if any(level in line for level in ['INFO', 'WARNING', 'ERROR', 'CRITICAL'])]
                     filtered_content = "".join(filtered_lines)
                     current_gui_content = self.log_text.get("1.0", END)
                     if filtered_content.strip() != current_gui_content.strip():
                         scroll_pos = self.log_text.yview()
                         self.log_text.configure(state="normal")
                         self.log_text.delete("1.0", END)
                         self.log_text.insert(END, filtered_content)
                         self.log_text.yview_moveto(scroll_pos[0])
                         if scroll_pos[1] > 0.95: self.log_text.see(END)
                         self.log_text.configure(state="disabled")
                 elif self.log_text.get("1.0", END).strip():
                      self.log_text.configure(state="normal"); self.log_text.delete("1.0", END); self.log_text.configure(state="disabled")
             except Exception as e:
                 log.error(f"Error updating log display: {e}", exc_info=True)
                 try:
                     self.log_text.configure(state="normal"); self.log_text.delete("1.0", END); self.log_text.insert(END, f"Error loading logs: {e}"); self.log_text.configure(state="disabled")
                 except Exception: pass

    # --- Metody od process_alert do redraw_whitelist_list ---
    # (bez zmian)
    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, self.alert_unauthorized, vendor_id, product_id, bsd_name)
    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"⚠️ Unauthorized Device: {vendor_id}:{product_id}")
        self.alert_label.pack(pady=5, before=self.status_frame)
    def redraw_device_list(self):
        if not hasattr(self, 'device_list_frame') or not self.device_list_frame.winfo_exists(): return
        checked_ids = self.get_selected_device_ids()
        for widget in self.device_list_frame.winfo_children(): widget.destroy()
        self.device_checkboxes = {}
        sorted_devices = sorted(list(self.devices), key=lambda x: (x[0], x[1]))
        for i, (vendor_id, product_id, *_) in enumerate(sorted_devices):
            device_id_str = f"{vendor_id}:{product_id}"
            is_authorized = is_device_whitelisted(vendor_id, product_id)
            status_text = "Authorized" if is_authorized else "Unauthorized"
            icon = "✅ " if is_authorized else "❌ "
            text_color = "#2ECC71" if is_authorized else "#E74C3C"
            item_frame = ctk.CTkFrame(self.device_list_frame, fg_color="transparent")
            item_frame.pack(fill="x", pady=2, padx=5)
            checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
            checkbox = ctk.CTkCheckBox(item_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20)
            checkbox.pack(side="left", padx=(0, 5))
            self.device_checkboxes[device_id_str] = checkbox_var
            label_text = f"{icon}{device_id_str} - {status_text}"
            label = ctk.CTkLabel(item_frame, text=label_text, text_color=text_color, font=("Segoe UI", 14), anchor="w")
            label.pack(side="left", fill="x", expand=True)
        if self.unauthorized_device:
            vid, pid, _ = self.unauthorized_device
            is_still_unauthorized = any(d[0] == vid and d[1] == pid and not is_device_whitelisted(vid, pid) for d in self.devices)
            if not is_still_unauthorized:
                self.unauthorized_device = None
                if hasattr(self, 'alert_label') and self.alert_label.winfo_exists(): self.alert_label.pack_forget()
    def redraw_whitelist_list(self):
         if not hasattr(self, 'whitelist_list_frame') or not self.whitelist_list_frame.winfo_exists(): return
         checked_ids = self.get_selected_whitelist_ids()
         for widget in self.whitelist_list_frame.winfo_children(): widget.destroy()
         self.whitelist_checkboxes = {}
         conn = None
         try:
             conn = sqlite3.connect(DB_FILE)
             cursor = conn.execute("SELECT vendor_id, product_id FROM whitelist ORDER BY vendor_id, product_id")
             whitelisted_devices = cursor.fetchall()
         except sqlite3.Error as e: log.error(f"Nie można pobrać białej listy: {e}"); whitelisted_devices = []
         finally:
             if conn: conn.close()
         for vendor_id, product_id in whitelisted_devices:
             device_id_str = f"{vendor_id}:{product_id}"
             item_frame = ctk.CTkFrame(self.whitelist_list_frame, fg_color="transparent"); item_frame.pack(fill="x", pady=2, padx=5)
             checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
             checkbox = ctk.CTkCheckBox(item_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20); checkbox.pack(side="left", padx=(0, 5))
             self.whitelist_checkboxes[device_id_str] = checkbox_var
             label_text = f"✔️ {device_id_str}"
             label = ctk.CTkLabel(item_frame, text=label_text, text_color="#2ECC71", font=("Segoe UI", 14), anchor="w"); label.pack(side="left", fill="x", expand=True)

    # --- ZMIENIONA FUNKCJA EJECT ---
    def eject_selected_devices(self):
        """Wysuwa zaznaczone urządzenia z listy podłączonych."""
        selected_ids = self.get_selected_device_ids()
        if not selected_ids:
            messagebox.showwarning("Brak zaznaczenia", "Zaznacz podłączone urządzenia, które chcesz wysunąć.")
            return

        ejected_count = 0
        failed_count = 0
        devices_to_remove_from_set = set() # Krotki do usunięcia z self.devices

        for device_id in selected_ids:
            vendor_id, product_id = device_id.split(":")
            bsd_name = None
            device_tuple = None

            # Znajdź BSD Name i pełną krotkę dla wybranego urządzenia
            for dev_tuple in self.devices:
                if dev_tuple[0] == vendor_id and dev_tuple[1] == product_id:
                    bsd_name = dev_tuple[2]
                    device_tuple = dev_tuple
                    break

            if platform.system() == "Darwin" and bsd_name and device_tuple:
                log.info(f"Próba wysunięcia {device_id} (BSD: {bsd_name})...")
                try:
                    subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True, timeout=10)
                    log.info(f"Pomyślnie wysunięto {device_id}.")
                    ejected_count += 1
                    devices_to_remove_from_set.add(device_tuple) # Dodaj do usunięcia z self.devices
                    # Sprawdź, czy to było urządzenie powodujące alert
                    if self.unauthorized_device and self.unauthorized_device[0] == vendor_id and self.unauthorized_device[1] == product_id:
                        self.unauthorized_device = None
                except subprocess.CalledProcessError as e:
                    log.error(f"Nie udało się wysunąć {device_id}: {e.stderr.decode('utf-8', 'ignore')}")
                    messagebox.showerror("Błąd wysuwania", f"Nie udało się wysunąć {device_id}:\n{e.stderr.decode('utf-8', 'ignore')}")
                    failed_count += 1
                except subprocess.TimeoutExpired:
                     log.error(f"Polecenie wysunięcia {device_id} przekroczyło limit czasu.")
                     messagebox.showerror("Błąd wysuwania", f"Polecenie wysunięcia {device_id} nie odpowiedziało w oczekiwanym czasie.")
                     failed_count += 1
                except Exception as e:
                     log.error(f"Nieoczekiwany błąd podczas wysuwania {device_id}: {e}", exc_info=True)
                     messagebox.showerror("Błąd wysuwania", f"Wystąpił nieoczekiwany błąd podczas wysuwania {device_id}: {e}")
                     failed_count += 1
            elif platform.system() != "Darwin":
                 messagebox.showwarning("Nieobsługiwane", f"Wysuwanie nie jest wspierane na {platform.system()}.")
                 failed_count += len(selected_ids) # Zlicz wszystkie jako nieudane
                 break # Nie ma sensu próbować dalej
            elif not bsd_name:
                 log.warning(f"Nie można wysunąć {device_id}: Brak BSD Name.")
                 messagebox.showwarning("Brak informacji", f"Nie można wysunąć {device_id}: Brak identyfikatora systemowego (BSD Name).")
                 failed_count += 1
            # else: Nie znaleziono device_tuple - dziwne, ale pomijamy

        # Usuń pomyślnie wysunięte urządzenia z self.devices
        if devices_to_remove_from_set:
            self.devices.difference_update(devices_to_remove_from_set) # difference_update usuwa elementy

        # Poinformuj użytkownika o wyniku
        msg = ""
        if ejected_count > 0: msg += f"Pomyślnie wysunięto {ejected_count} urządzeń.\n"
        if failed_count > 0: msg += f"Nie udało się wysunąć {failed_count} urządzeń."
        if msg: messagebox.showinfo("Wynik wysuwania", msg.strip())

        self.force_refresh_gui() # Odśwież interfejs, aby pokazać zmiany
    # --- KONIEC ZMIENIONEJ FUNKCJI EJECT ---


    def get_selected_device_ids(self):
        return [dev_id for dev_id, var in self.device_checkboxes.items() if var.get() != "off"]
    def get_selected_whitelist_ids(self):
         return [dev_id for dev_id, var in self.whitelist_checkboxes.items() if var.get() != "off"]
    def add_selected_to_whitelist(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids: messagebox.showwarning("Brak zaznaczenia", "Zaznacz podłączone urządzenia do dodania."); return
        added_count, skipped_count = 0, 0
        for device_id in selected_ids:
            try:
                vendor_id, product_id = device_id.split(":")
                if not is_device_whitelisted(vendor_id, product_id): add_to_whitelist(vendor_id, product_id); added_count += 1
                else: skipped_count += 1
            except Exception as e: log.error(f"Błąd dodawania {device_id}: {e}"); messagebox.showerror("Błąd", f"Nie udało się dodać {device_id}: {e}")
        msg = f"Dodano {added_count} urządzeń.\n" if added_count else ""
        msg += f"Pominięto {skipped_count} (już na liście)." if skipped_count else ""
        if msg: messagebox.showinfo("Wynik dodawania", msg.strip())
        self.force_refresh_gui()
    def remove_selected_from_whitelist_list(self):
        selected_ids = self.get_selected_whitelist_ids()
        if not selected_ids: messagebox.showwarning("Brak zaznaczenia", "Zaznacz na liście 'Whitelisted Devices' urządzenia do usunięcia."); return
        confirm = messagebox.askyesno("Potwierdzenie", f"Usunąć {len(selected_ids)} urządzeń z białej listy?")
        if not confirm: return
        removed_count = 0
        for device_id in selected_ids:
            try:
                vendor_id, product_id = device_id.split(":")
                remove_from_whitelist(vendor_id, product_id); removed_count += 1
            except Exception as e: log.error(f"Błąd usuwania {device_id}: {e}"); messagebox.showerror("Błąd", f"Nie udało się usunąć {device_id}: {e}")
        msg = f"Usunięto {removed_count} urządzeń.\n" if removed_count else ""
        if msg: messagebox.showinfo("Wynik usuwania", msg.strip())
        self.force_refresh_gui()
    def check_alert_queue(self):
        while not alert_queue.empty(): self.alert_unauthorized(*alert_queue.get())
        self.after(100, self.check_alert_queue)
    def export_logs_csv(self):
        log.info("Exporting logs to CSV...")
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE)
            results = conn.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC").fetchall()
            if not results: messagebox.showinfo("Export CSV", "No logs to export."); return
            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f); writer.writerow(["Timestamp", "VendorID", "ProductID", "Action"]); writer.writerows(results)
            messagebox.showinfo("Export CSV", f"Logs exported to {filename}")
        except Exception as e: log.error(f"CSV export error: {e}"); messagebox.showerror("Error", f"Could not export logs: {e}")
        finally:
            if conn: conn.close()
    def export_logs_json(self):
        log.info("Exporting logs to JSON...")
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
            results = conn.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC").fetchall()
            if not results: messagebox.showinfo("Export JSON", "No logs to export."); return
            log_list = [dict(row) for row in results]
            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f: json.dump(log_list, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Export JSON", f"Logs exported to {filename}")
        except Exception as e: log.error(f"JSON export error: {e}"); messagebox.showerror("Error", f"Could not export logs: {e}")
        finally:
            if conn: conn.close()

    def scan_selected_device(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids: messagebox.showwarning("Brak zaznaczenia", "Zaznacz podłączone urządzenie do skanowania."); return
        first_selected_id = selected_ids[0]
        log.info(f"Rozpoczynanie skanowania dla: {first_selected_id}")
        vendor_id, product_id = first_selected_id.split(":")
        bsd_name = next((dev[2] for dev in self.devices if dev[0] == vendor_id and dev[1] == product_id), None)
        if not bsd_name: messagebox.showerror("Error", f"Nie można znaleźć informacji systemowych dla {first_selected_id}."); return
        mount_point = get_mount_point(bsd_name)
        if not mount_point: messagebox.showerror("Error", f"Nie można zlokalizować punktu montowania dla {first_selected_id}."); return
        self.is_scanning = True; self.etr_label.configure(text=""); self.status_label.configure(text="Przygotowywanie...")
        self.progress.configure(mode="indeterminate"); self.progress.start()
        for btn in [self.scan_button, self.refresh_button, self.add_button, self.remove_button]: btn.configure(state="disabled")
        self.process_scan_queue()
        scan_thread = Thread(target=self.run_scan, args=(mount_point,), daemon=True); scan_thread.start()
    def run_scan(self, mount_point):
        scan_result_dict = scan_device(mount_point, self.scan_progress_queue)
        self.scan_progress_queue.put({"done": True, "result": scan_result_dict})
    def process_scan_queue(self):
        try:
            latest_progress_update, final_message = None, None
            while not self.scan_progress_queue.empty():
                update = self.scan_progress_queue.get_nowait()
                if "done" in update: final_message = update; break
                elif "error" in update: final_message = {"done": True, "result": {"error": update["error"]}}; break
                elif "progress" in update: latest_progress_update = update
                elif "status" in update and self.progress.cget("mode") == "indeterminate": self.status_label.configure(text=update["status"])
            if latest_progress_update:
                if self.progress.cget("mode") == "indeterminate": self.progress.stop(); self.progress.configure(mode="determinate")
                self.progress.set(latest_progress_update["progress"])
                self.status_label.configure(text=latest_progress_update.get("status", ""))
                self.etr_label.configure(text=latest_progress_update.get("etr", ""))
            if final_message: self.show_scan_results(final_message["result"]); return
            if self.is_scanning: self.after(100, self.process_scan_queue)
        except Exception as e: log.error(f"Błąd w pętli przetwarzania kolejki: {e}"); self.show_scan_results({"error": f"Błąd interfejsu: {e}"})
    def show_scan_results(self, result_dict):
        self.is_scanning = False
        for btn in [self.scan_button, self.refresh_button, self.add_button, self.remove_button]:
             if hasattr(btn, 'configure') and btn.winfo_exists(): btn.configure(state="normal")
        if hasattr(self, 'progress') and self.progress.winfo_exists():
             if self.progress.cget("mode") == "indeterminate": self.progress.stop()
             self.progress.configure(mode="determinate"); self.progress.set(1.0)
        if hasattr(self, 'status_label') and self.status_label.winfo_exists(): self.status_label.configure(text="Skanowanie zakończone.")
        if hasattr(self, 'etr_label') and self.etr_label.winfo_exists(): self.etr_label.configure(text="")
        if result_dict.get("error"): error_msg = result_dict["error"]; log.error(f"Błąd skanowania: {error_msg}"); messagebox.showerror("Błąd Skanowania", error_msg); return
        infected_files = result_dict.get("infected", []); warnings = result_dict.get("warnings", []); scanned_files_list = result_dict.get("scanned_files", [])
        warning_message = f"\n\n(Uwaga: {warnings[0].splitlines()[0]})" if warnings else ""
        if not infected_files: log.info("Wynik: Czysto."); self.show_clean_scan_dialog(scanned_files_list, warning_message)
        else: log.warning(f"Wynik: Znaleziono {len(infected_files)} infekcji."); self.show_infected_scan_dialog(infected_files, scanned_files_list, warning_message)
    def show_clean_scan_dialog(self, scanned_files_list, warning_message):
        dialog = ctk.CTkToplevel(self); dialog.title("Wynik Skanowania"); dialog.geometry("400x150"); dialog.transient(self); dialog.grab_set()
        main_label = ctk.CTkLabel(dialog, text=f"✅ Nie znaleziono infekcji.{warning_message}", font=("Segoe UI", 14)); main_label.pack(pady=20, padx=20)
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent"); button_frame.pack(pady=10)
        ok_button = ctk.CTkButton(button_frame, text="OK", command=dialog.destroy, width=100); ok_button.pack(side="left", padx=10)
        details_button = ctk.CTkButton(button_frame, text="Zobacz szczegóły", command=lambda: self.show_scanned_files_window(scanned_files_list), width=180); details_button.pack(side="left", padx=10)
    def show_infected_scan_dialog(self, infected_files, scanned_files_list, warning_message):
        results_window = ctk.CTkToplevel(self); results_window.title("Wyniki - Znaleziono zagrożenia!"); results_window.geometry("800x600"); results_window.transient(self); results_window.grab_set()
        label = ctk.CTkLabel(results_window, text=f"UWAGA: Znaleziono {len(infected_files)} zainfekowanych plików:{warning_message}", font=("Segoe UI", 16, "bold"), text_color="#E74C3C"); label.pack(pady=10)
        textbox = ctk.CTkTextbox(results_window, width=780, height=500); textbox.pack(padx=10, pady=(0,10))
        for item in infected_files: textbox.insert(END, f"{item['path']} (Sygnatura: {item['signature']})\n")
        button_frame = ctk.CTkFrame(results_window, fg_color="transparent"); button_frame.pack(pady=10)
        details_button = ctk.CTkButton(button_frame, text="Pokaż wszystkie przeskanowane", command=lambda: self.show_scanned_files_window(scanned_files_list)); details_button.pack(padx=10)
    def show_scanned_files_window(self, scanned_files_list):
        details_window = ctk.CTkToplevel(self); details_window.title("Szczegóły - Przeskanowane Pliki"); details_window.geometry("900x700"); details_window.transient(self); details_window.grab_set()
        label = ctk.CTkLabel(details_window, text=f"Lista {len(scanned_files_list)} przeskanowanych plików:", font=("Segoe UI", 16)); label.pack(pady=10)
        textbox = ctk.CTkTextbox(details_window, width=880, height=650); textbox.pack(padx=10, pady=(0,10))
        textbox.insert("1.0", "\n".join(scanned_files_list)); textbox.configure(state="disabled")

if __name__ == "__main__":
    # Upewnij się, że logger jest skonfigurowany przed startem GUI
    # (Zakładając, że main.py to robi - jeśli uruchamiasz gui.py bezpośrednio, dodaj tu setup_logger())
    # from logger import setup_logger # Jeśli potrzebne
    # setup_logger()                 # Jeśli potrzebne
    
    # Sprawdzenie platformy przed startem
    if platform.system() != "Darwin":
        messagebox.showwarning("Niekompatybilny system", "Ta aplikacja jest zoptymalizowana dla macOS. Na innych systemach może nie działać poprawnie.")
        # Można tu dodać `return` lub `sys.exit()`, jeśli aplikacja ma działać *tylko* na macOS

    app = USBMonitorApp()
    app.mainloop()