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

try:
    import psutil
except ImportError:
    psutil = None

try:
    import usb.core
    import usb.util
except ImportError:
    pass

from .usb_monitor import get_connected_devices, monitor_usb, set_alert_callback, alert_queue
from .database import is_device_whitelisted, add_to_whitelist, remove_from_whitelist
from .scanner import scan_device, get_mount_point
from config import LOG_FILE, DB_FILE

log = logging.getLogger('secure_usb.gui')

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MacScan")
        self.geometry("1400x900")
        
        self.ejected_devices = set()
        self.start_time = datetime.now()
        
        # --- Konfiguracja Ikony ---
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(current_dir, "..", "assets", "logo.png")
            if os.path.exists(icon_path):
                image = Image.open(icon_path)
                photo = ImageTk.PhotoImage(image)
                self.wm_iconphoto(True, photo)
        except Exception:
            pass

        self.configure(fg_color="#0F172A")
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
        
        # --- NAGŁÓWEK ---
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E293B", corner_radius=6)
        self.header_frame.pack(fill="x", pady=(0, 15))
        
        self.header_label = ctk.CTkLabel(
            self.header_frame, 
            text="MacScan Security", 
            font=("Helvetica", 24, "bold"), 
            text_color="#F8FAFC"
        )
        self.header_label.pack(pady=15, padx=20, anchor="w")
        
        # --- KOLUMNY ---
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure(0, weight=4)
        self.content_frame.grid_columnconfigure(1, weight=3)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEWA STRONA ---
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="#1E293B", corner_radius=6)
        self.left_frame.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=1)
        self.left_frame.grid_rowconfigure(3, weight=1)
        
        ctk.CTkLabel(self.left_frame, text="CONNECTED DEVICES", font=("Helvetica", 13, "bold"), text_color="#94A3B8").grid(row=0, column=0, pady=(15, 5), padx=15, sticky="w")
        
        self.device_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#0F172A", corner_radius=4)
        self.device_list_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        
        ctk.CTkLabel(self.left_frame, text="WHITELIST", font=("Helvetica", 13, "bold"), text_color="#94A3B8").grid(row=2, column=0, pady=(15, 5), padx=15, sticky="w")
        
        self.whitelist_list_frame = ctk.CTkScrollableFrame(self.left_frame, fg_color="#0F172A", corner_radius=4)
        self.whitelist_list_frame.grid(row=3, column=0, padx=15, pady=(0, 15), sticky="nsew")
        
        # --- PRAWA STRONA ---
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.right_frame.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(0, weight=3)
        self.right_frame.grid_rowconfigure(1, weight=1)
        
        self.tabview = ctk.CTkTabview(self.right_frame, fg_color="#1E293B", segmented_button_fg_color="#0F172A", segmented_button_selected_color="#3B82F6", text_color="#E2E8F0")
        self.tabview.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.tabview.add("Activity Log")
        self.tabview.add("Data Export")
        
        self.log_text = ctk.CTkTextbox(self.tabview.tab("Activity Log"), font=("Menlo", 12), fg_color="#0F172A", text_color="#CBD5E1", wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_text.configure(state="disabled")
        
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Data Export"), fg_color="transparent")
        self.export_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.export_csv_button = ctk.CTkButton(self.export_frame, text="Export CSV", command=self.export_logs_csv, fg_color="#3B82F6", height=35)
        self.export_csv_button.pack(pady=10, fill="x")
        
        self.export_json_button = ctk.CTkButton(self.export_frame, text="Export JSON", command=self.export_logs_json, fg_color="#3B82F6", height=35)
        self.export_json_button.pack(pady=10, fill="x")
        
        # Statystyki
        self.stats_frame = ctk.CTkFrame(self.right_frame, fg_color="#1E293B", corner_radius=6)
        self.stats_frame.grid(row=1, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.stats_frame, text="SYSTEM HEALTH", font=("Helvetica", 13, "bold"), text_color="#94A3B8").pack(pady=(15, 10), padx=15, anchor="w")
        
        self.cpu_label = ctk.CTkLabel(self.stats_frame, text="CPU: 0%", font=("Helvetica", 12), text_color="#E2E8F0")
        self.cpu_label.pack(padx=15, anchor="w")
        self.cpu_bar = ctk.CTkProgressBar(self.stats_frame, height=8, progress_color="#10B981", fg_color="#334155")
        self.cpu_bar.pack(fill="x", padx=15, pady=(0, 10))
        
        self.ram_label = ctk.CTkLabel(self.stats_frame, text="RAM: 0%", font=("Helvetica", 12), text_color="#E2E8F0")
        self.ram_label.pack(padx=15, anchor="w")
        self.ram_bar = ctk.CTkProgressBar(self.stats_frame, height=8, progress_color="#8B5CF6", fg_color="#334155")
        self.ram_bar.pack(fill="x", padx=15, pady=(0, 10))
        
        self.uptime_label = ctk.CTkLabel(self.stats_frame, text="Uptime: 00:00:00", font=("Helvetica", 12), text_color="#64748B")
        self.uptime_label.pack(padx=15, pady=(5, 15), anchor="e")

        # --- PRZYCISKI AKCJI ---
        self.actions_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E293B", corner_radius=6)
        self.actions_frame.pack(fill="x", pady=(15, 0))
        
        self.buttons_row = ctk.CTkFrame(self.actions_frame, fg_color="transparent")
        self.buttons_row.pack(fill="x", padx=15, pady=15)
        
        self.add_button = ctk.CTkButton(self.buttons_row, text="Whitelist Selected", command=self.add_selected_to_whitelist, fg_color="#10B981", width=140)
        self.add_button.pack(side="left", padx=(0,10))
        
        self.remove_button = ctk.CTkButton(self.buttons_row, text="Remove Selected", command=self.remove_selected_from_whitelist_list, fg_color="#EF4444", width=140)
        self.remove_button.pack(side="left", padx=(0,10))
        
        self.scan_button = ctk.CTkButton(self.buttons_row, text="Scan Device", command=self.scan_selected_device, fg_color="#F59E0B", width=120)
        self.scan_button.pack(side="left", padx=(0,10))
        
        self.block_button = ctk.CTkButton(self.buttons_row, text="Eject Device", command=self.start_eject_thread, fg_color="#BE123C", width=120)
        self.block_button.pack(side="left", padx=(0,10))
        
        self.refresh_button = ctk.CTkButton(self.buttons_row, text="Refresh", command=self.force_refresh_gui, fg_color="#64748B", width=100)
        self.refresh_button.pack(side="right")

        # --- PASEK STANU ---
        self.status_bar_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.status_bar_frame.pack(fill="x", pady=(10, 0))
        
        self.progress = ctk.CTkProgressBar(self.status_bar_frame, height=10, progress_color="#3B82F6", fg_color="#334155")
        self.progress.set(0)
        self.progress.pack(fill="x", pady=(0, 5))
        
        self.status_label = ctk.CTkLabel(self.status_bar_frame, text="Ready", font=("Helvetica", 12), text_color="#94A3B8")
        self.status_label.pack(side="left")
        
        self.alert_label = ctk.CTkLabel(self.main_frame, text="", font=("Helvetica", 14, "bold"), text_color="#EF4444")

    # --- LOGIKA APLIKACJI ---

    def update_gui_loop(self):
            try:
                # To wykonuj ZAWSZE (niezależnie od skanowania)
                self.update_system_stats()

                # To wykonuj tylko gdy NIE skanujesz (żeby nie kolidowało z GUI skanera)
                if not self.is_scanning:
                    self.redraw_whitelist_list()
                    self.update_log_display()
                    
            except Exception:
                pass
            finally:
                self.after(2000, self.update_gui_loop)

    def update_system_stats(self):
        if not psutil:
            return
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_bar.set(cpu_percent / 100)
            self.cpu_label.configure(text=f"CPU: {cpu_percent}%")
            
            ram = psutil.virtual_memory()
            self.ram_bar.set(ram.percent / 100)
            self.ram_label.configure(text=f"RAM: {ram.percent}%")
            
            uptime = datetime.now() - self.start_time
            self.uptime_label.configure(text=f"Uptime: {str(uptime).split('.')[0]}")
        except Exception:
            pass

    def update_device_list_from_monitor(self, current_devices):
        if self.is_scanning:
            return
            
        self.devices = current_devices
        
        # Logika usuwania alertu (autoryzacja / odłączenie)
        if self.unauthorized_device:
             unauth_vid, unauth_pid, *_ = self.unauthorized_device
             is_still_connected = any(d[0] == unauth_vid and d[1] == unauth_pid for d in self.devices)
             is_now_allowed = is_device_whitelisted(unauth_vid, unauth_pid)
             
             if not is_still_connected or is_now_allowed:
                 self.unauthorized_device = None
                 if hasattr(self, 'alert_label'):
                     self.alert_label.pack_forget()

        # Aktualizacja listy ejected
        current_ids_set = {(d[0], d[1]) for d in self.devices}
        self.ejected_devices = {d for d in self.ejected_devices if d in current_ids_set}
        
        self.redraw_device_list()

    def force_refresh_gui(self):
        self.redraw_device_list()
        self.redraw_whitelist_list()
        self.update_log_display()

    def update_log_display(self):
        if hasattr(self, 'log_text') and self.log_text.winfo_exists():
            try:
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, 'r', encoding='utf-8') as f:
                        all_lines = f.readlines()[-100:]
                    filtered_lines = [line for line in all_lines if any(level in line for level in ['INFO', 'WARNING', 'ERROR', 'CRITICAL'])]
                    content = "".join(filtered_lines)
                    
                    if content.strip() != self.log_text.get("1.0", END).strip():
                        self.log_text.configure(state="normal")
                        self.log_text.delete("1.0", END)
                        self.log_text.insert(END, content)
                        self.log_text.see(END)
                        self.log_text.configure(state="disabled")
            except Exception:
                pass

    def process_alert(self, vendor_id, product_id, bsd_name, device_classes):
        self.after(0, self.alert_unauthorized, vendor_id, product_id, bsd_name, device_classes)

    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None, device_classes=[]):
        if (vendor_id, product_id) in self.ejected_devices:
            if hasattr(self, 'alert_label'):
                self.alert_label.pack_forget()
            return
            
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        
        classes_list = device_classes if device_classes else []
        
        # Domyślny alert
        alert_text = f"UNAUTHORIZED: {vendor_id}:{product_id}"
        alert_color = "#EF4444"
        
        # --- DOSTOSOWANE KOMUNIKATY ---
        if "HUB" in classes_list and "HID" in classes_list:
            alert_text = f"CRITICAL: SUSPICIOUS HUB/KEYBOARD COMBO! ({vendor_id}:{product_id})"
            alert_color = "#FF0000" # Czerwony alarm - BadUSB?
        elif "HID" in classes_list:
            alert_text = f"WARNING: UNAUTHORIZED KEYBOARD/MOUSE DETECTED! ({vendor_id}:{product_id})"
            alert_color = "#FF4444"
        elif "STORAGE" in classes_list: # --- NOWE: Ostrzeżenie dla Storage ---
            alert_text = f"WARNING: UNAUTHORIZED STORAGE DETECTED! ({vendor_id}:{product_id})"
            alert_color = "#EF4444" # Standardowy czerwony
        elif "NETWORK" in classes_list or "WIRELESS" in classes_list:
            alert_text = f"CRITICAL: UNAUTHORIZED NETWORK ADAPTER! ({vendor_id}:{product_id})"
            alert_color = "#FF0000"
        elif "AUDIO" in classes_list or "VIDEO" in classes_list:
            alert_text = f"WARNING: UNAUTHORIZED SURVEILLANCE DEVICE (Audio/Video)!"
            alert_color = "#FFA500" # Pomarańczowy
        elif "HUB" in classes_list:
            alert_text = f"NOTICE: UNAUTHORIZED HUB DETECTED ({vendor_id}:{product_id})"
            alert_color = "#FFCC00" # Żółty
             
        self.alert_label.configure(text=alert_text, text_color=alert_color)
        self.alert_label.pack(pady=(0, 10), before=self.header_frame)

    def redraw_device_list(self):
        if not hasattr(self, 'device_list_frame'):
            return
            
        checked_ids = self.get_selected_device_ids()
        for widget in self.device_list_frame.winfo_children():
            widget.destroy()
        self.device_checkboxes = {}
        
        sorted_devices = sorted(list(self.devices), key=lambda x: (x[0], x[1]))
        
        if not sorted_devices:
            ctk.CTkLabel(self.device_list_frame, text="No devices connected", text_color="#64748B").pack(pady=10)

        for i, (vendor_id, product_id, bsd_name, device_name, classes_tuple) in enumerate(sorted_devices):
            device_id_str = f"{vendor_id}:{product_id}"
            is_ejected = (vendor_id, product_id) in self.ejected_devices
            is_authorized = is_device_whitelisted(vendor_id, product_id)
            
            classes_list = list(classes_tuple)
            
            status_text = "Ejected" if is_ejected else ("Authorized" if is_authorized else "Unauthorized")
            status_color = "#64748B" if is_ejected else ("#10B981" if is_authorized else "#EF4444")

            row_frame = ctk.CTkFrame(self.device_list_frame, fg_color="transparent")
            row_frame.pack(fill="x", pady=2, padx=5)
            
            checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
            checkbox = ctk.CTkCheckBox(row_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20, border_width=2, fg_color="#3B82F6")
            checkbox.pack(side="left", padx=(0, 10))
            self.device_checkboxes[device_id_str] = checkbox_var
            
            label_text = f"{device_id_str} ({device_name})"
            for cls in classes_list:
                label_text += f" [{cls}]"
            
            name_label = ctk.CTkLabel(row_frame, text=label_text, text_color="#E2E8F0" if not is_ejected else "#475569", font=("Helvetica", 13), anchor="w")
            name_label.pack(side="left", fill="x", expand=True)
            
            status_label = ctk.CTkLabel(row_frame, text=status_text, text_color=status_color, font=("Helvetica", 11, "bold"), anchor="e")
            status_label.pack(side="right", padx=5)

    def redraw_whitelist_list(self):
        if not hasattr(self, 'whitelist_list_frame'):
            return
            
        checked_ids = self.get_selected_whitelist_ids()
        for widget in self.whitelist_list_frame.winfo_children():
            widget.destroy()
        self.whitelist_checkboxes = {}
        
        whitelist_data = []
        try:
            conn = sqlite3.connect(DB_FILE)
            whitelist_data = conn.execute("SELECT vendor_id, product_id, device_name FROM whitelist").fetchall()
            conn.close()
        except Exception:
            whitelist_data = []
            
        if not whitelist_data:
            ctk.CTkLabel(self.whitelist_list_frame, text="Whitelist Empty", text_color="#64748B").pack(pady=10)
            
        for row in whitelist_data:
            vendor_id = row[0]
            product_id = row[1]
            device_name = row[2] if len(row) > 2 and row[2] else "Unknown Device"
            
            device_id_str = f"{vendor_id}:{product_id}"
            display_text = f"{device_id_str} ({device_name})"
            
            row_frame = ctk.CTkFrame(self.whitelist_list_frame, fg_color="transparent")
            row_frame.pack(fill="x", pady=2, padx=5)
            
            checkbox_var = ctk.StringVar(value=device_id_str if device_id_str in checked_ids else "off")
            checkbox = ctk.CTkCheckBox(row_frame, text="", variable=checkbox_var, onvalue=device_id_str, offvalue="off", width=20, border_width=2, fg_color="#3B82F6")
            checkbox.pack(side="left", padx=(0, 10))
            self.whitelist_checkboxes[device_id_str] = checkbox_var
            
            ctk.CTkLabel(row_frame, text=display_text, text_color="#10B981", font=("Helvetica", 13), anchor="w").pack(side="left", fill="x", expand=True)

    def start_eject_thread(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids:
            messagebox.showwarning("Select", "Select devices to eject.")
            return
        self.block_button.configure(state="disabled", text="Ejecting...")
        Thread(target=self.run_eject_process, args=(selected_ids,), daemon=True).start()

    def run_eject_process(self, selected_ids):
        ejected_count = 0
        failed_count = 0
        
        for device_id_str in selected_ids:
            vendor_id, product_id = device_id_str.split(":")
            bsd_name = None
            for device_tuple in self.devices:
                if device_tuple[0] == vendor_id and device_tuple[1] == product_id:
                    bsd_name = device_tuple[2]
                    break

            if platform.system() == "Darwin" and bsd_name:
                success = False
                for attempt in range(5):
                    try:
                        subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True, capture_output=True, timeout=10)
                        success = True
                        break
                    except Exception:
                        time.sleep(2)
                
                if success:
                    ejected_count += 1
                    self.ejected_devices.add((vendor_id, product_id))
                    if self.unauthorized_device and self.unauthorized_device[0] == vendor_id and self.unauthorized_device[1] == product_id:
                        self.unauthorized_device = None
                        self.after(0, lambda: self.alert_label.pack_forget())
                else:
                    failed_count += 1
            else:
                failed_count += 1
                
        self.after(0, self.finish_eject, ejected_count, failed_count)

    def finish_eject(self, ejected_count, failed_count):
        self.redraw_device_list()
        self.block_button.configure(state="normal", text="Eject Device")
        if failed_count > 0:
            messagebox.showerror("Result", f"Failed to eject {failed_count} devices.")

    def get_selected_device_ids(self):
        return [dev_id for dev_id, var in self.device_checkboxes.items() if var.get() != "off"]

    def get_selected_whitelist_ids(self):
        return [dev_id for dev_id, var in self.whitelist_checkboxes.items() if var.get() != "off"]
    
    def add_selected_to_whitelist(self):
        for device_id_str in self.get_selected_device_ids():
            try:
                vendor_id, product_id = device_id_str.split(":")
                
                device_name = "Unknown Device"
                for dev in self.devices:
                    if dev[0] == vendor_id and dev[1] == product_id:
                        device_name = dev[3] 
                        break
                
                add_to_whitelist(vendor_id, product_id, device_name)
            except Exception:
                pass
                
        if self.unauthorized_device:
            unauth_vid, unauth_pid, *_ = self.unauthorized_device
            if is_device_whitelisted(unauth_vid, unauth_pid):
                self.unauthorized_device = None
                self.alert_label.pack_forget()
                
        self.force_refresh_gui()

    def remove_selected_from_whitelist_list(self):
        selected_ids = self.get_selected_whitelist_ids()
        if not selected_ids:
            return
        if not messagebox.askyesno("Confirm", f"Remove {len(selected_ids)} devices from whitelist?"):
            return
            
        for device_id_str in selected_ids:
            try:
                vendor_id, product_id = device_id_str.split(":")
                remove_from_whitelist(vendor_id, product_id)
            except Exception:
                pass
        self.force_refresh_gui()
    
    def check_alert_queue(self):
        while not alert_queue.empty():
            self.alert_unauthorized(*alert_queue.get())
        self.after(100, self.check_alert_queue)

    def export_logs_csv(self):
        try:
            os.makedirs("logs/exports", exist_ok=True)
            conn = sqlite3.connect(DB_FILE)
            results = conn.execute("SELECT * FROM logs").fetchall()
            conn.close()
            
            if not results:
                return
                
            filename = f"logs/exports/log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow(["ID", "Timestamp", "VendorID", "ProductID", "Action"])
                csv.writer(f).writerows(results)
            messagebox.showinfo("Saved", f"Log saved to: {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        
    def export_logs_json(self):
        try:
            os.makedirs("logs/exports", exist_ok=True)
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            results = conn.execute("SELECT * FROM logs").fetchall()
            conn.close()
            
            if not results:
                return
                
            filename = f"logs/exports/log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([dict(row) for row in results], f, indent=4)
            messagebox.showinfo("Saved", f"Log saved to: {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def scan_selected_device(self):
        selected_ids = self.get_selected_device_ids()
        if not selected_ids:
            return
            
        vendor_id, product_id = selected_ids[0].split(":")
        bsd_name = next((d[2] for d in self.devices if d[0] == vendor_id and d[1] == product_id), None)
        if not bsd_name:
            messagebox.showerror("Error", "Device not mounted (no BSD Name).")
            return
            
        mount_point = get_mount_point(bsd_name)
        if not mount_point:
            messagebox.showerror("Error", "Cannot find mount point for this device.")
            return
            
        self.scan_progress_queue = Queue()
        self.is_scanning = True
        self.status_label.configure(text="Scanning...")
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        
        self.process_scan_queue()
        Thread(target=self.run_scan, args=(mount_point,), daemon=True).start()

    def run_scan(self, mount_point):
        scan_result = scan_device(mount_point, self.scan_progress_queue)
        self.scan_progress_queue.put({"done": True, "result": scan_result})

    def process_scan_queue(self):
        try:
            final_message = None
            while not self.scan_progress_queue.empty():
                update = self.scan_progress_queue.get_nowait()
                if "done" in update:
                    final_message = update
                    break
                elif "status" in update:
                    self.status_label.configure(text=update["status"])
                    
            if final_message:
                self.show_scan_results(final_message["result"])
                return
                
            if self.is_scanning:
                self.after(100, self.process_scan_queue)
        except Exception:
            self.show_scan_results({"error": "Queue processing error"})

    def show_scan_results(self, scan_result):
        self.is_scanning = False
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1.0)
        self.status_label.configure(text="Scan Finished")
        
        if scan_result.get("error"):
            messagebox.showerror("Error", scan_result["error"])
            return
            
        if not scan_result.get("infected"):
            self.show_clean_scan_dialog(scan_result.get("scanned_files", []))
        else:
            self.show_infected_scan_dialog(scan_result["infected"])

    def show_clean_scan_dialog(self, scanned_files):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Scan Results")
        dialog.geometry("400x150")
        
        ctk.CTkLabel(dialog, text="No Threats Found.", font=("Helvetica", 14, "bold"), text_color="#10B981").pack(pady=20)
        ctk.CTkButton(dialog, text="Show Log", command=lambda: self.show_scanned_files_window(scanned_files)).pack(pady=10)

    def show_infected_scan_dialog(self, infected_files):
        dialog = ctk.CTkToplevel(self)
        dialog.title("THREATS DETECTED")
        dialog.geometry("600x400")
        
        ctk.CTkLabel(dialog, text=f"THREATS FOUND: {len(infected_files)}", font=("Helvetica", 16, "bold"), text_color="#EF4444").pack(pady=15)
        
        text_box = ctk.CTkTextbox(dialog, width=550, height=250)
        text_box.pack(pady=5)
        for file in infected_files:
            text_box.insert(END, f"{file['path']} ({file['signature']})\n")

    def show_scanned_files_window(self, scanned_files):
        window = ctk.CTkToplevel(self)
        window.title("Scanned Files Log")
        window.geometry("600x500")
        
        text_box = ctk.CTkTextbox(window, width=580, height=480)
        text_box.pack(pady=10)
        text_box.insert("1.0", "\n".join(scanned_files))

if __name__ == "__main__":
    app = USBMonitorApp()
    app.mainloop()