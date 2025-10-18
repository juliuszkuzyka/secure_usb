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

from .usb_monitor import get_connected_devices, monitor_usb, set_alert_callback, alert_queue
from .database import is_device_whitelisted, add_to_whitelist, remove_from_whitelist
from .scanner import scan_device, get_mount_point
from config import LOG_FILE, DB_FILE

log = logging.getLogger('secure_usb.gui')

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        log.info("Starting USBMonitorApp")
        self.title("USB Security Monitor")
        self.geometry("1400x900")
        self.configure(fg_color="#0D1B2A")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.devices = set()
        self.selected_device = None
        self.unauthorized_device = None
        
        # Bezpieczna kolejka do komunikacji między wątkami
        self.scan_progress_queue = Queue()

        self.setup_ui()
        set_alert_callback(self.process_alert)
        Thread(target=monitor_usb, daemon=True).start()
        self.check_alert_queue()
        self.update_gui()

    def setup_ui(self):
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
        self.left_frame.grid_rowconfigure(1, weight=1)
        self.device_label = ctk.CTkLabel(self.left_frame, text="📟 Connected USB Devices", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.device_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")
        self.device_textbox = Text(self.left_frame, height=10, font=("Segoe UI", 14), bg="#2D2D2D", fg="#D4D4D4", insertbackground="#D4D4D4", wrap="none", cursor="hand2")
        self.device_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.device_textbox.bind("<Button-1>", self.on_device_select)
        self.whitelist_label = ctk.CTkLabel(self.left_frame, text="✅ Whitelisted Devices", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.whitelist_label.grid(row=2, column=0, pady=(10, 5), padx=10, sticky="w")
        self.whitelist_textbox = ctk.CTkTextbox(self.left_frame, height=200, font=("Segoe UI", 14), fg_color="#2D2D2D", text_color="#D4D4D4", corner_radius=8, wrap="none")
        self.whitelist_textbox.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="#1B263B", corner_radius=10)
        self.right_frame.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)
        self.log_label = ctk.CTkLabel(self.right_frame, text="📜 Recent Events", font=("Segoe UI", 18, "bold"), text_color="#E0E1DD")
        self.log_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")
        self.tabview = ctk.CTkTabview(self.right_frame, fg_color="#2D2D2D", segmented_button_fg_color="#415A77", segmented_button_selected_color="#778DA9", text_color="#E0E1DD")
        self.tabview.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.tabview.add("Logs")
        self.tabview.add("Export")
        self.log_text = ctk.CTkTextbox(self.tabview.tab("Logs"), height=400, font=("Consolas", 13), corner_radius=8, fg_color="#2D2D2D", text_color="#D4D4D4", wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2D2D2D")
        self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # --- POPRAWKA BŁĘDU FOKUSU ---
        self.export_csv_button = ctk.CTkButton(self.export_frame, text="Export CSV 📄", command=self.export_logs_csv, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 14), corner_radius=8)
        self.export_csv_button.pack(pady=10)
        
        self.export_json_button = ctk.CTkButton(self.export_frame, text="Export JSON 📋", command=self.export_logs_json, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 14), corner_radius=8)
        self.export_json_button.pack(pady=10)
        # --- KONIEC POPRAWKI ---
        
        self.buttons_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.buttons_frame.pack(fill="x", pady=10)
        self.add_button = ctk.CTkButton(self.buttons_frame, text="Add to Whitelist ➕", command=self.add_to_whitelist, fg_color="#2ECC71", hover_color="#27AE60", font=("Segoe UI", 14), corner_radius=8, width=200)
        self.add_button.pack(side="left", padx=5)
        self.remove_button = ctk.CTkButton(self.buttons_frame, text="Remove from Whitelist ➖", command=self.remove_from_whitelist, fg_color="#E74C3C", hover_color="#C0392B", font=("Segoe UI", 14), corner_radius=8, width=200)
        self.remove_button.pack(side="left", padx=5)
        self.scan_button = ctk.CTkButton(self.buttons_frame, text="Scan 🔍", command=self.scan_selected_device, fg_color="#F39C12", hover_color="#D35400", font=("Segoe UI", 14), corner_radius=8, width=200)
        self.scan_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(self.buttons_frame, text="Refresh 🔄", command=self.update_gui, fg_color="#3498DB", hover_color="#2980B9", font=("Segoe UI", 14), corner_radius=8, width=200)
        self.refresh_button.pack(side="left", padx=5)
        self.block_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.block_frame.pack(fill="x", pady=5)
        self.block_button = ctk.CTkButton(self.block_frame, text="Eject Unauthorized Device 🚫", command=self.eject_device, fg_color="#E74C3C", hover_color="#C0392B", font=("Segoe UI", 14), corner_radius=8, width=300)
        self.block_button.pack(pady=5)
        self.progress = ctk.CTkProgressBar(self.main_frame, width=700, progress_color="#3498DB", fg_color="#2D2D2D")
        self.progress.set(0)
        self.progress.pack(pady=10)
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.status_frame.pack(fill="x", pady=5)
        self.status_label = ctk.CTkLabel(self.status_frame, text="Monitoring USB devices... 🔍", font=("Segoe UI", 14), text_color="#A0A0A0", anchor="w")
        self.status_label.pack(side="left", padx=10, fill="x", expand=True)
        self.etr_label = ctk.CTkLabel(self.status_frame, text="", font=("Segoe UI", 14), text_color="#A0A0A0", anchor="e")
        self.etr_label.pack(side="right", padx=10)
        self.alert_label = ctk.CTkLabel(self.main_frame, text="", font=("Segoe UI", 16, "bold"), text_color="#E74C3C")

    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, self.alert_unauthorized, vendor_id, product_id, bsd_name)
    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"⚠️ Unauthorized Device: {vendor_id}:{product_id}")
        self.alert_label.pack(pady=5, before=self.status_frame)
    def redraw_device_list(self):
        self.device_textbox.delete("1.0", END)
        sorted_devices = sorted(list(self.devices), key=lambda x: (x[0], x[1]))
        for i, (vendor_id, product_id, *_) in enumerate(sorted_devices):
            status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
            icon = "✅ " if status == "Authorized" else "❌ "
            entry = f"{icon}{vendor_id}:{product_id} - {status}\n"
            self.device_textbox.insert(END, entry)
            self.device_textbox.tag_add(status, f"{i+1}.0", f"{i+1}.end")
        self.device_textbox.tag_configure("Authorized", foreground="#2ECC71")
        self.device_textbox.tag_configure("Unauthorized", foreground="#E74C3C")
        if self.unauthorized_device:
            vid, pid, _ = self.unauthorized_device
            is_still_unauthorized = any(d[0] == vid and d[1] == pid and not is_device_whitelisted(vid, pid) for d in self.devices)
            if not is_still_unauthorized:
                self.unauthorized_device = None
                self.alert_label.pack_forget()
    def eject_device(self):
        if not self.unauthorized_device:
            messagebox.showinfo("Info", "No unauthorized device to eject.")
            return
        vendor_id, product_id, bsd_name = self.unauthorized_device
        if platform.system() == "Darwin":
            if not bsd_name:
                messagebox.showwarning("Warning", "Cannot eject: Device not identified.")
                return
            try:
                subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True)
                messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} ejected.")
                self.devices.discard(self.unauthorized_device)
                self.unauthorized_device = None
                self.update_gui()
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to eject device: {e.stderr.decode('utf-8', 'ignore')}")
        else:
            messagebox.showwarning("Warning", "Eject not supported on this system.")
    def on_device_select(self, event):
        try:
            line_num_str = self.device_textbox.index(f"@{event.x},{event.y}").split('.')[0]
            line_content = self.device_textbox.get(f"{line_num_str}.0", f"{line_num_str}.end").strip()
            if not line_content:
                self.selected_device = None
                self.device_textbox.tag_remove("selected", "1.0", END)
                return
            self.selected_device = line_content.split(' ')[1]
            self.device_textbox.tag_remove("selected", "1.0", END)
            self.device_textbox.tag_add("selected", f"{line_num_str}.0", f"{line_num_str}.end")
            self.device_textbox.tag_configure("selected", background="#4A90E2", foreground="#FFFFFF")
            self.status_label.configure(text=f"Selected: {self.selected_device}")
        except Exception:
            self.selected_device = None
            self.device_textbox.tag_remove("selected", "1.0", END)
    def remove_from_whitelist(self):
        if not self.selected_device:
            messagebox.showwarning("Warning", "Please select a device.")
            return
        vendor_id, product_id = self.selected_device.split(":")
        remove_from_whitelist(vendor_id, product_id)
        messagebox.showinfo("Success", f"Device {self.selected_device} removed from whitelist.")
        self.update_gui()
    def update_gui(self):
        try:
            if self.scan_button.cget("state") == "disabled":
                self.after(5000, self.update_gui)
                return
            self.devices = get_connected_devices()
            self.redraw_device_list()
            self.whitelist_textbox.delete("1.0", END)
            conn = sqlite3.connect(DB_FILE)
            for vid, pid in conn.execute("SELECT vendor_id, product_id FROM whitelist"):
                self.whitelist_textbox.insert(END, f"✔️ {vid}:{pid}\n")
            conn.close()
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding='utf-8') as f:
                    content = f.read()
                    current_content = self.log_text.get("1.0", END)
                    if content.strip() != current_content.strip():
                        self.log_text.delete("1.0", END)
                        self.log_text.insert(END, content)
                        self.log_text.see(END)
        except Exception as e:
            log.error(f"GUI update error: {e}", exc_info=True)
        finally:
            self.after(5000, self.update_gui)
    def check_alert_queue(self):
        while not alert_queue.empty():
            self.alert_unauthorized(*alert_queue.get())
        self.after(100, self.check_alert_queue)
    def add_to_whitelist(self):
        if not self.selected_device:
            messagebox.showwarning("Warning", "Please select a device.")
            return
        vendor_id, product_id = self.selected_device.split(":")
        add_to_whitelist(vendor_id, product_id)
        messagebox.showinfo("Success", f"Device {self.selected_device} added to whitelist.")
        self.update_gui()

    def export_logs_csv(self):
        log.info("Rozpoczynanie eksportu logów do CSV...")
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC")
            results = c.fetchall()
            
            if not results:
                messagebox.showinfo("Eksport CSV", "Brak logów do wyeksportowania.")
                return

            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "VendorID", "ProductID", "Action"])
                writer.writerows(results)
            
            log.info(f"Pomyślnie wyeksportowano {len(results)} wpisów do {filename}")
            messagebox.showinfo("Eksport CSV", f"Pomyślnie wyeksportowano logi do {filename}")

        except sqlite3.Error as e:
            log.error(f"Błąd bazy danych podczas eksportu CSV: {e}")
            messagebox.showerror("Błąd", f"Błąd bazy danych: {e}")
        except Exception as e:
            log.error(f"Nieoczekiwany błąd podczas eksportu CSV: {e}")
            messagebox.showerror("Błąd", f"Nieoczekiwany błąd: {e}")
        finally:
            if conn:
                conn.close()

    def export_logs_json(self):
        log.info("Rozpoczynanie eksportu logów do JSON...")
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC")
            results = c.fetchall()
            
            if not results:
                messagebox.showinfo("Eksport JSON", "Brak logów do wyeksportowania.")
                return

            log_list = [dict(row) for row in results]

            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(log_list, f, indent=4, ensure_ascii=False)
            
            log.info(f"Pomyślnie wyeksportowano {len(log_list)} wpisów do {filename}")
            messagebox.showinfo("Eksport JSON", f"Pomyślnie wyeksportowano logi do {filename}")

        except sqlite3.Error as e:
            log.error(f"Błąd bazy danych podczas eksportu JSON: {e}")
            messagebox.showerror("Błąd", f"Błąd bazy danych: {e}")
        except Exception as e:
            log.error(f"Nieoczekiwany błąd podczas eksportu JSON: {e}")
            messagebox.showerror("Błąd", f"Nieoczekiwany błąd: {e}")
        finally:
            if conn:
                conn.close()

    def scan_selected_device(self):
        if not self.selected_device:
            messagebox.showwarning("Warning", "Please select a device to scan.")
            return
        
        vendor_id, product_id = self.selected_device.split(":")
        bsd_name = next((dev[2] for dev in self.devices if dev[0] == vendor_id and dev[1] == product_id), None)
        
        if not bsd_name:
            messagebox.showerror("Error", "Cannot identify the path for this device.")
            return
            
        mount_point = get_mount_point(bsd_name)
        if not mount_point:
            messagebox.showerror("Error", "Could not locate the device's mount point.")
            return

        self.etr_label.configure(text="")
        self.status_label.configure(text="Przygotowywanie...")
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        
        for btn in [self.scan_button, self.refresh_button, self.add_button, self.remove_button]:
            btn.configure(state="disabled")

        self.process_scan_queue()
        
        scan_thread = Thread(target=self.run_scan, args=(mount_point,), daemon=True)
        scan_thread.start()

    def run_scan(self, mount_point):
        """Uruchamia skaner i umieszcza finałowy wynik w kolejce."""
        infected_files = scan_device(mount_point, self.scan_progress_queue)
        self.scan_progress_queue.put({"done": True, "result": infected_files})

    def process_scan_queue(self):
        """Przetwarza komunikaty z kolejki, aby zaktualizować GUI."""
        try:
            while not self.scan_progress_queue.empty():
                update = self.scan_progress_queue.get_nowait()
                
                if "error" in update:
                    self.show_scan_results({"error": update["error"]})
                    return
                
                if "done" in update:
                    self.show_scan_results(update["result"])
                    return

                if "status" in update and self.progress.cget("mode") == "indeterminate":
                    self.status_label.configure(text=update["status"])
                
                if "progress" in update:
                    if self.progress.cget("mode") == "indeterminate":
                        self.progress.stop()
                        self.progress.configure(mode="determinate")
                    
                    self.progress.set(update["progress"])
                    self.status_label.configure(text=update.get("status", ""))
                    self.etr_label.configure(text=update.get("etr", ""))
            
            self.after(100, self.process_scan_queue)

        except Exception as e:
            log.error(f"Błąd w pętli przetwarzania kolejki: {e}")

    def show_scan_results(self, result):
        """Wyświetla końcowy wynik skanowania."""
        for btn in [self.scan_button, self.refresh_button, self.add_button, self.remove_button]:
            btn.configure(state="normal")

        if self.progress.cget("mode") == "indeterminate":
            self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1.0)
        self.status_label.configure(text="Skanowanie zakończone.")
        self.etr_label.configure(text="")
        
        if isinstance(result, dict) and "error" in result:
            messagebox.showerror("Scan Error", result["error"])
            return

        infected_files = result
        if not infected_files:
            messagebox.showinfo("Scan Results", "Nie znaleziono zainfekowanych plików.")
        else:
            results_window = ctk.CTkToplevel(self)
            results_window.title("Wyniki skanowania - Znaleziono zagrożenia!")
            results_window.geometry("800x600")
            label = ctk.CTkLabel(results_window, text=f"UWAGA: Znaleziono {len(infected_files)} zainfekowanych plików:", font=("Segoe UI", 16, "bold"), text_color="#E74C3C")
            label.pack(pady=10)
            textbox = ctk.CTkTextbox(results_window, width=780, height=550)
            textbox.pack(padx=10, pady=10)
            for file in infected_files:
                textbox.insert(END, file + "\n")

if __name__ == "__main__":
    app = USBMonitorApp()
    app.mainloop()