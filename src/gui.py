# src/gui.py

import customtkinter as ctk
import logging
import os
import sqlite3
from threading import Thread
from tkinter import messagebox, END
from datetime import datetime
import csv
import json
import subprocess
import platform
import time
from queue import Queue
from PIL import Image, ImageTk

# Dodajemy psutil do monitorowania zasobów (jest w requirements.txt)
try:
    import psutil
except ImportError:
    psutil = None

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
        log.info("Starting MacScan")
        self.title("MacScan")
        self.geometry("1400x900")
        
        self.ejected_devices = set()
        self.start_time = datetime.now()

        # --- Ładowanie ikony ---
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(current_dir, "..", "assets", "logo.png")
            if os.path.exists(icon_path):
                image = Image.open(icon_path)
                photo = ImageTk.PhotoImage(image)
                self.wm_iconphoto(True, photo)
            else:
                log.warning(f"Icon file not found at: {icon_path}")
        except Exception as e:
            log.warning(f"Could not load application icon: {e}")
        # -----------------------

        self.configure(fg_color="#0F172A") # Slate 900
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        self.devices = set()
        self.unauthorized_device = None 
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
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # --- HEADER ---
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E293B", corner_radius=6)
        self.header_frame.pack(fill="x", pady=(0, 15))
        
        self.header_label = ctk.CTkLabel(
            self.header_frame, 
            text="MacScan Security", 
            font=("Helvetica", 24, "bold"), 
            text_color="#F8FAFC", 
            anchor="w"
        )
        self.header_label.pack(pady=15, padx=20)
        
        # --- CONTENT (Columns) ---
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure(0, weight=4)
        self.content_frame.grid_columnconfigure(1, weight=3)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT COLUMN ---
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="#1E293B", corner_radius=6)
        self.left_frame.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=1)
        self.left_frame.grid_rowconfigure(3, weight=1)
        
        self.device_label = ctk.CTkLabel(self.left_frame, text="CONNECTED DEVICES", font=("Helvetica", 13, "bold"), text_color="#94A3B8", anchor="w")
        self.device_label.grid(row=0, column=0, pady=(15, 5), padx=15, sticky="w")
        
        self.device_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#0F172A", corner_radius=4)
        self.device_list_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        
        self.whitelist_label = ctk.CTkLabel(self.left_frame, text="WHITELIST", font=("Helvetica", 13, "bold"), text_color="#94A3B8", anchor="w")
        self.whitelist_label.grid(row=2, column=0, pady=(15, 5), padx=15, sticky="w")
        
        self.whitelist_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#0F172A", corner_radius=4)
        self.whitelist_list_frame.grid(row=3, column=0, padx=15, pady=(0, 15), sticky="nsew")
        
        # --- RIGHT COLUMN ---
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.right_frame.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(0, weight=3) # Logs larger
        self.right_frame.grid_rowconfigure(1, weight=1) # Stats smaller
        
        # Tabs (Logs)
        self.tabview = ctk.CTkTabview(self.right_frame, fg_color="#1E293B", segmented_button_fg_color="#0F172A", segmented_button_selected_color="#3B82F6", text_color="#E2E8F0", corner_radius=6)
        self.tabview.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.tabview.add("Activity Log")
        self.tabview.add("Data Export")
        
        self.log_text = ctk.CTkTextbox(self.tabview.tab("Activity Log"), font=("Menlo", 12), fg_color="#0F172A", text_color="#CBD5E1", wrap="none", corner_radius=4)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_text.configure(state="disabled")
        
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Data Export"), fg_color="transparent")
        self.export_frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.export_csv_button = ctk.CTkButton(self.export_frame, text="Export to CSV", command=self.export_logs_csv, fg_color="#3B82F6", hover_color="#2563EB", height=35)
        self.export_csv_button.pack(pady=10, fill="x")
        self.export_json_button = ctk.CTkButton(self.export_frame, text="Export to JSON", command=self.export_logs_json, fg_color="#3B82F6", hover_color="#2563EB", height=35)
        self.export_json_button.pack(pady=10, fill="x")
        
        # --- SYSTEM HEALTH DASHBOARD ---
        self.stats_frame = ctk.CTkFrame(self.right_frame, fg_color="#1E293B", corner_radius=6)
        self.stats_frame.grid(row=1, column=0, sticky="nsew")
        
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="SYSTEM HEALTH", font=("Helvetica", 13, "bold"), text_color="#94A3B8")
        self.stats_label.pack(pady=(15, 10), padx=15, anchor="w")
        
        # CPU
        self.cpu_label = ctk.CTkLabel(self.stats_frame, text="CPU Usage: 0%", font=("Helvetica", 12), text_color="#E2E8F0")
        self.cpu_label.pack(padx=15, anchor="w")
        self.cpu_bar = ctk.CTkProgressBar(self.stats_frame, height=8, progress_color="#10B981", fg_color="#334155")
        self.cpu_bar.pack(fill="x", padx=15, pady=(0, 10))
        
        # RAM
        self.ram_label = ctk.CTkLabel(self.stats_frame, text="RAM Usage: 0%", font=("Helvetica", 12), text_color="#E2E8F0")
        self.ram_label.pack(padx=15, anchor="w")
        self.ram_bar = ctk.CTkProgressBar(self.stats_frame, height=8, progress_color="#8B5CF6", fg_color="#334155")
        self.ram_bar.pack(fill="x", padx=15, pady=(0, 10))
        
        # Uptime
        self.uptime_label = ctk.CTkLabel(self.stats_frame, text="Session Uptime: 00:00:00", font=("Helvetica", 12), text_color="#64748B")
        self.uptime_label.pack(padx=15, pady=(5, 15), anchor="e")

        # --- ACTION BUTTONS ---
        self.actions_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E293B", corner_radius=6)
        self.actions_frame.pack(fill="x", pady=(15, 0))
        
        self.buttons_row = ctk.CTkFrame(self.actions_frame, fg_color="transparent")
        self.buttons_row.pack(fill="x", padx=15, pady=15)
        
        # Lewa strona przycisków
        self.add_button = ctk.CTkButton(self.buttons_row, text="Whitelist Selected", command=self.add_selected_to_whitelist, fg_color="#10B981", hover_color="#059669", width=140)
        self.add_button.pack(side="left", padx=(0, 10))
        
        self.remove_button = ctk.CTkButton(self.buttons_row, text="Remove from Whitelist", command=self.remove_selected_from_whitelist_list, fg_color="#EF4444", hover_color="#DC2626", width=160)
        self.remove_button.pack(side="left", padx=(0, 10))
        
        # Środek - Skanowanie i Eject
        self.scan_button = ctk.CTkButton(self.buttons_row, text="Scan Device", command=self.scan_selected_device, fg_color="#F59E0B", hover_color="#D97706", width=120)
        self.scan_button.pack(side="left", padx=(0, 10))
        
        self.block_button = ctk.CTkButton(self.buttons_row, text="Eject Device", command=self.start_eject_thread, fg_color="#BE123C", hover_color="#9F1239", width=120)
        self.block_button.pack(side="left", padx=(0, 10))
        
        # Prawa strona
        self.refresh_button = ctk.CTkButton(self.buttons_row, text="Refresh", command=self.force_refresh_gui, fg_color="#64748B", hover_color="#475569", width=100)
        self.refresh_button.pack(side="right")

        # Status bar
        self.status_bar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.status_bar.pack(fill="x", pady=(10, 0))
        
        self.progress = ctk.CTkProgressBar(self.status_bar, height=10, progress_color="#3B82F6", fg_color="#334155")
        self.progress.set(0)
        self.progress.pack(fill="x", pady=(0, 5))
        
        self.status_label = ctk.CTkLabel(self.status_bar, text="System Ready", font=("Helvetica", 12), text_color="#94A3B8", anchor="w")
        self.status_label.pack(side="left")
        self.alert_label = ctk.CTkLabel(self.main_frame, text="", font=("Helvetica", 14, "bold"), text_color="#EF4444")

    # --- LOGIKA GUI ---

    def update_gui_loop(self):
        try:
            if not self.is_scanning:
                self.redraw_whitelist_list()
                self.update_log_display()
                self.update_system_stats() # Aktualizacja panelu dashboard
        except Exception as e:
            log.error(f"GUI update loop error: {e}")
        finally:
            self.after(2000, self.update_gui_loop)

    def update_system_stats(self):
        if not psutil: return
        try:
            # CPU
            cpu_usage = psutil.cpu_percent(interval=None)
            self.cpu_bar.set(cpu_usage / 100)
            self.cpu_label.configure(text=f"CPU Usage: {cpu_usage}%")
            
            # RAM
            ram = psutil.virtual_memory()
            self.ram_bar.set(ram.percent / 100)
            self.ram_label.configure(text=f"RAM Usage: {ram.percent}% ({round(ram.used/1024/1024/1024, 1)} GB used)")
            
            # Uptime
            delta = datetime.now() - self.start_time
            self.uptime_label.configure(text=f"Session Uptime: {str(delta).split('.')[0]}")
            
        except Exception as e:
            log.error(f"Stats update error: {e}")

    def update_device_list_from_monitor(self, current_devices_set):
         if not self.is_scanning:
             self.devices = current_devices_set
             current_ids = {(d[0], d[1]) for d in self.devices}
             self.ejected_devices = {d for d in self.ejected_devices if d in current_ids}
             self.redraw_device_list()

    def force_refresh_gui(self):
         self.redraw_device_list()
         self.redraw_whitelist_list()
         self.update_log_display()

    def update_log_display(self):
         if hasattr(self, 'log_text') and self.log_text.winfo_exists():
             try:
                 if os.path.exists(LOG_FILE):
                     with open(LOG_FILE, "r", encoding='utf-8') as f: 
                         all_lines = f.readlines()[-100:]
                     filtered_lines = [line for line in all_lines if any(level in line for level in ['INFO', 'WARNING', 'ERROR', 'CRITICAL'])]
                     filtered_content = "".join(filtered_lines)
                     current_gui_content = self.log_text.get("1.0", END)
                     if filtered_content.strip() != current_gui_content.strip():
                         self.log_text.configure(state="normal")
                         self.log_text.delete("1.0", END)
                         self.log_text.insert(END, filtered_content)
                         self.log_text.see(END)
                         self.log_text.configure(state="disabled")
             except Exception: pass

    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, self.alert_unauthorized, vendor_id, product_id, bsd_name)

    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        if (vendor_id, product_id) in self.ejected_devices:
            if hasattr(self, 'alert_label') and self.alert_label.winfo_exists(): 
                self.alert_label.pack_forget()
            return
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"UNAUTHORIZED DEVICE DETECTED: {vendor_id}:{product_id}")
        self.alert_label.pack(pady=(0, 10), before=self.header_frame)

    def redraw_device_list(self):
        if not hasattr(self, 'device_list_frame') or not self.device_list_frame.winfo_exists(): return
        
        checked_ids = self.get_selected_device_ids()
        for widget in self.device_list_frame.winfo_children(): widget.destroy()
        self.device_checkboxes = {}
        
        sorted_devices = sorted(list(self.devices), key=lambda x: (x[0], x[1]))
        
        if not sorted_devices:
             ctk.CTkLabel(self.device_list_frame, text="No devices connected", text_color="#64748B").pack(pady=10)

        for i, (vendor_id, product_id, *_) in enumerate(sorted_devices):
            device_id_str = f"{vendor_id}:{product_id}"
            
            is_ejected = (vendor_id, product_id) in self.ejected_devices
            is_authorized = is_device_whitelisted(vendor_id, product_id)
            
            if is_ejected:
                status_text = "Ejected"
                main_color = "#64748B"
                status_color = "#64748B"
            elif is_authorized:
                status_text = "Authorized"
                main_color = "#10B981"
                status_color = "#10B981"
            else:
                status_text = "Unauthorized"
                main_color = "#EF4444"
                status_color = "#EF4444"

            item_frame = ctk.CTkFrame(self.device_list_frame, fg_color="transparent")
            item_frame.pack(fill="x", pady=2, padx=5)
            
            checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
            checkbox = ctk.CTkCheckBox(item_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20, corner_radius=4, border_width=2, fg_color="#3B82F6")
            checkbox.pack(side="left", padx=(0, 10))
            self.device_checkboxes[device_id_str] = checkbox_var
            
            label_text = f"{device_id_str}"
            name_label = ctk.CTkLabel(item_frame, text=label_text, text_color="#E2E8F0" if not is_ejected else "#475569", font=("Helvetica", 13), anchor="w")
            name_label.pack(side="left", fill="x", expand=True)
            status_label = ctk.CTkLabel(item_frame, text=status_text, text_color=status_color, font=("Helvetica", 11, "bold"), anchor="e")
            status_label.pack(side="right", padx=5)

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
         except sqlite3.Error: whitelisted_devices = []
         finally:
             if conn: conn.close()
             
         if not whitelisted_devices:
             ctk.CTkLabel(self.whitelist_list_frame, text="Whitelist empty", text_color="#64748B").pack(pady=10)

         for vendor_id, product_id in whitelisted_devices:
             device_id_str = f"{vendor_id}:{product_id}"
             item_frame = ctk.CTkFrame(self.whitelist_list_frame, fg_color="transparent"); item_frame.pack(fill="x", pady=2, padx=5)
             checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
             checkbox = ctk.CTkCheckBox(item_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20, corner_radius=4, border_width=2, fg_color="#3B82F6")
             checkbox.pack(side="left", padx=(0, 10))
             self.whitelist_checkboxes[device_id_str] = checkbox_var
             ctk.CTkLabel(item_frame, text=device_id_str, text_color="#10B981", font=("Helvetica", 13), anchor="w").pack(side="left", fill="x", expand=True)

    # --- OBSŁUGA EJECT W OSOBNYM WĄTKU ---
    
    def start_eject_thread(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids:
            messagebox.showwarning("Selection Required", "Please select connected devices to eject.")
            return
        self.block_button.configure(state="disabled", text="Ejecting...")
        Thread(target=self.run_eject_process, args=(selected_ids,), daemon=True).start()

    def run_eject_process(self, selected_ids):
        ejected_count = 0
        failed_count = 0
        for device_id in selected_ids:
            vendor_id, product_id = device_id.split(":")
            bsd_name = None
            for dev_tuple in self.devices:
                if dev_tuple[0] == vendor_id and dev_tuple[1] == product_id:
                    bsd_name = dev_tuple[2]
                    break

            if platform.system() == "Darwin" and bsd_name:
                log.info(f"Attempting eject for {device_id} (BSD: {bsd_name})...")
                success = False
                try:
                    subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True, timeout=5)
                    success = True
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    log.warning(f"First eject attempt failed for {bsd_name}. Retrying...")
                    time.sleep(1)
                    try:
                        subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True, timeout=5)
                        success = True
                    except Exception as e:
                        log.error(f"Final eject failed for {device_id}: {e}")
                
                if success:
                    log.info(f"Successfully ejected {device_id}.")
                    ejected_count += 1
                    self.ejected_devices.add((vendor_id, product_id))
                    if self.unauthorized_device and self.unauthorized_device[0] == vendor_id and self.unauthorized_device[1] == product_id:
                        self.unauthorized_device = None
                else:
                    failed_count += 1
            else:
                 log.warning(f"Cannot eject {device_id}: No BSD Name.")
                 failed_count += 1

        self.after(0, self.finish_eject, ejected_count, failed_count)

    def finish_eject(self, ejected_count, failed_count):
        self.redraw_device_list()
        self.block_button.configure(state="normal", text="Eject Device")
        if failed_count > 0:
             messagebox.showerror("Eject Result", f"Failed to eject {failed_count} devices. Try again.")

    # --- METODY POMOCNICZE ---

    def get_selected_device_ids(self):
        return [dev_id for dev_id, var in self.device_checkboxes.items() if var.get() != "off"]
    def get_selected_whitelist_ids(self):
         return [dev_id for dev_id, var in self.whitelist_checkboxes.items() if var.get() != "off"]
         
    def add_selected_to_whitelist(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids: return
        for device_id in selected_ids:
            try:
                vendor_id, product_id = device_id.split(":")
                if not is_device_whitelisted(vendor_id, product_id): add_to_whitelist(vendor_id, product_id)
            except Exception: pass
        self.force_refresh_gui()
        
    def remove_selected_from_whitelist_list(self):
        selected_ids = self.get_selected_whitelist_ids()
        if not selected_ids: return
        if not messagebox.askyesno("Confirm", f"Remove {len(selected_ids)} devices?"): return
        for device_id in selected_ids:
            try:
                vendor_id, product_id = device_id.split(":")
                remove_from_whitelist(vendor_id, product_id)
            except Exception: pass
        self.force_refresh_gui()
        
    def check_alert_queue(self):
        while not alert_queue.empty(): self.alert_unauthorized(*alert_queue.get())
        self.after(100, self.check_alert_queue)
        
    def export_logs_csv(self):
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE)
            results = conn.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC").fetchall()
            if not results: messagebox.showinfo("Export", "No logs."); return
            
            # ZMIANA: Folder logs/exports
            export_dir = os.path.join("logs", "exports")
            os.makedirs(export_dir, exist_ok=True)
            
            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            filepath = os.path.join(export_dir, filename)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f); writer.writerow(["Timestamp", "VendorID", "ProductID", "Action"]); writer.writerows(results)
            messagebox.showinfo("Export", f"Saved to {filepath}")
        except Exception as e: messagebox.showerror("Error", str(e))
        finally:
            if conn: conn.close()
            
    def export_logs_json(self):
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
            results = conn.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id ASC").fetchall()
            if not results: messagebox.showinfo("Export", "No logs."); return
            
            # ZMIANA: Folder logs/exports
            export_dir = os.path.join("logs", "exports")
            os.makedirs(export_dir, exist_ok=True)
            
            log_list = [dict(row) for row in results]
            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(export_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f: json.dump(log_list, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Export", f"Saved to {filepath}")
        except Exception as e: messagebox.showerror("Error", str(e))
        finally:
            if conn: conn.close()

    def scan_selected_device(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids: messagebox.showwarning("Selection", "Select a device."); return
        first_selected_id = selected_ids[0]
        
        vendor_id, product_id = first_selected_id.split(":")
        bsd_name = next((dev[2] for dev in self.devices if dev[0] == vendor_id and dev[1] == product_id), None)
        if not bsd_name: messagebox.showerror("Error", "Device not mounted."); return
        
        mount_point = get_mount_point(bsd_name)
        if not mount_point: messagebox.showerror("Error", "Cannot locate mount point."); return
        
        self.is_scanning = True
        self.status_label.configure(text="Preparing scan...")
        self.progress.configure(mode="indeterminate"); self.progress.start()
        self.process_scan_queue()
        Thread(target=self.run_scan, args=(mount_point,), daemon=True).start()
        
    def run_scan(self, mount_point):
        scan_result_dict = scan_device(mount_point, self.scan_progress_queue)
        self.scan_progress_queue.put({"done": True, "result": scan_result_dict})
        
    def process_scan_queue(self):
        try:
            final_message = None
            while not self.scan_progress_queue.empty():
                update = self.scan_progress_queue.get_nowait()
                if "done" in update: final_message = update; break
                elif "error" in update: final_message = {"done": True, "result": {"error": update["error"]}}; break
                elif "status" in update: self.status_label.configure(text=update["status"])
            
            if final_message: self.show_scan_results(final_message["result"]); return
            if self.is_scanning: self.after(100, self.process_scan_queue)
        except Exception as e: self.show_scan_results({"error": str(e)})
        
    def show_scan_results(self, result_dict):
        self.is_scanning = False
        if hasattr(self, 'progress') and self.progress.winfo_exists():
             self.progress.stop(); self.progress.configure(mode="determinate"); self.progress.set(1.0)
        self.status_label.configure(text="Scan finished.")
        
        if result_dict.get("error"): messagebox.showerror("Scan Error", result_dict["error"]); return
        
        infected = result_dict.get("infected", [])
        scanned = result_dict.get("scanned_files", [])
        
        if not infected: 
            self.show_clean_scan_dialog(scanned, "")
        else: 
            self.show_infected_scan_dialog(infected, scanned, "")

    def show_clean_scan_dialog(self, scanned_files_list, warning_message):
        dialog = ctk.CTkToplevel(self); dialog.title("Scan Results"); dialog.geometry("400x150")
        dialog.transient(self); dialog.grab_set()
        ctk.CTkLabel(dialog, text="No threats found.", font=("Helvetica", 14, "bold"), text_color="#10B981").pack(pady=20)
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent"); btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Close", command=dialog.destroy, width=100, fg_color="#64748B").pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Details", command=lambda: self.show_scanned_files_window(scanned_files_list), width=100).pack(side="left", padx=10)

    def show_infected_scan_dialog(self, infected_files, scanned_files_list, warning_message):
        win = ctk.CTkToplevel(self); win.title("Threats Found"); win.geometry("600x400")
        win.transient(self); win.grab_set()
        ctk.CTkLabel(win, text=f"WARNING: {len(infected_files)} THREATS DETECTED", font=("Helvetica", 16, "bold"), text_color="#EF4444").pack(pady=15)
        tb = ctk.CTkTextbox(win, width=550, height=250); tb.pack(pady=5)
        for f in infected_files: tb.insert(END, f"{f['path']} ({f['signature']})\n")
        ctk.CTkButton(win, text="Close", command=win.destroy, fg_color="#EF4444", hover_color="#DC2626").pack(pady=15)

    def show_scanned_files_window(self, scanned_files_list):
        win = ctk.CTkToplevel(self); win.title("Scanned Files Log"); win.geometry("600x500")
        tb = ctk.CTkTextbox(win, width=580, height=480); tb.pack(pady=10, padx=10)
        tb.insert("1.0", "\n".join(scanned_files_list)); tb.configure(state="disabled")

if __name__ == "__main__":
    if platform.system() != "Darwin":
        messagebox.showwarning("Compatibility", "This application is optimized for macOS.")
    app = USBMonitorApp()
    app.mainloop()