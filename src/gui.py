import customtkinter as ctk
import logging
import os
import sqlite3
from threading import Thread
from tkinter import messagebox, Listbox, END
from datetime import datetime
import csv
import json
import subprocess
import platform
from queue import Queue

from .usb_monitor import get_connected_devices, monitor_usb, set_alert_callback, alert_queue
from .database import is_device_whitelisted, add_to_whitelist, remove_from_whitelist
from config import LOG_FILE, DB_FILE

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("USB Security Monitor")
        self.geometry("1300x1000")
        self.configure(fg_color="#1A1A1A")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.devices = set()
        self.selected_device = None
        self.unauthorized_device = None
        self.setup_ui()
        set_alert_callback(self.process_alert)
        Thread(target=monitor_usb, daemon=True).start()
        self.check_alert_queue()
        self.update_gui()

    def setup_ui(self):
        self.header_label = ctk.CTkLabel(self, text="USB Security Monitor", font=("Segoe UI", 24, "bold"), text_color="#FFFFFF")
        self.header_label.pack(pady=15)

        self.device_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.device_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.device_label = ctk.CTkLabel(self.device_frame, text="Connected USB Devices", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.device_label.pack(pady=5)

        self.device_listbox = Listbox(self.device_frame, height=10, width=70, font=("Segoe UI", 13), bg="#2D2D2D", fg="#D4D4D4", selectbackground="#4A90E2", selectforeground="#FFFFFF")
        self.device_listbox.pack(pady=5)
        self.device_listbox.bind('<ButtonRelease-1>', self.on_device_select)

        self.whitelist_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.whitelist_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.whitelist_label = ctk.CTkLabel(self.whitelist_frame, text="Whitelisted Devices", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.whitelist_label.pack(pady=5)

        self.whitelist_listbox = ctk.CTkTextbox(self.whitelist_frame, height=100, width=700, font=("Segoe UI", 13), corner_radius=10, fg_color="#2D2D2D", text_color="#D4D4D4")
        self.whitelist_listbox.pack(pady=5)

        self.buttons_frame = ctk.CTkFrame(self, fg_color="#1A1A1A")
        self.buttons_frame.pack(pady=10, side="top")
        self.add_button = ctk.CTkButton(self.buttons_frame, text="Add to Whitelist", command=self.add_to_whitelist, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 12), corner_radius=8)
        self.add_button.pack(side="left", padx=5)
        self.remove_button = ctk.CTkButton(self.buttons_frame, text="Remove from Whitelist", command=self.remove_from_whitelist, fg_color="#FF5555", hover_color="#CC0000", font=("Segoe UI", 12), corner_radius=8)
        self.remove_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(self.buttons_frame, text="Refresh", command=self.update_gui, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 12), corner_radius=8)
        self.refresh_button.pack(side="left", padx=5)

        self.block_frame = ctk.CTkFrame(self, fg_color="#1A1A1A")
        self.block_frame.pack(pady=5, side="top")
        self.block_button = ctk.CTkButton(self.block_frame, text="Eject Unauthorized Device", command=self.eject_device, fg_color="#FF5555", hover_color="#CC0000", font=("Segoe UI", 12), corner_radius=8, state="disabled")
        self.block_button.pack(pady=5)

        self.progress = ctk.CTkProgressBar(self, width=700, progress_color="#4A90E2")
        self.progress.set(0)
        self.progress.pack(pady=5)

        self.log_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.log_label = ctk.CTkLabel(self.log_frame, text="Recent Events", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.log_label.pack(pady=5)

        self.tabview = ctk.CTkTabview(self.log_frame, fg_color="#2D2D2D", segmented_button_fg_color="#357ABD", segmented_button_selected_color="#4A90E2")
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)
        self.tabview.add("Logs")
        self.tabview.add("Export")

        self.log_text = ctk.CTkTextbox(self.tabview.tab("Logs"), height=150, width=700, font=("Consolas", 13), corner_radius=10, fg_color="#2D2D2D", text_color="#D4D4D4")
        self.log_text.pack(pady=5)

        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2D2D2D")
        self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkButton(self.export_frame, text="Export CSV", command=self.export_logs_csv, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 12), corner_radius=8).pack(pady=5)
        ctk.CTkButton(self.export_frame, text="Export JSON", command=self.export_logs_json, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 12), corner_radius=8).pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="Monitoring USB devices...", font=("Segoe UI", 13), text_color="#A0A0A0")
        self.status_label.pack(side="bottom", pady=5)

        self.alert_frame = ctk.CTkFrame(self, fg_color="#1A1A1A")
        self.alert_label = ctk.CTkLabel(self.alert_frame, text="", font=("Segoe UI", 14, "bold"), text_color="#FF5555")
        self.alert_label.pack(pady=5)

    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, lambda: self.alert_unauthorized(vendor_id, product_id, bsd_name))

    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"Unauthorized Device Detected: {vendor_id}:{product_id}")
        self.alert_frame.pack(pady=5)
        self.alert_frame.lift()
        logging.info(f"Alert triggered for {vendor_id}:{product_id}, bsd_name: {bsd_name}")
        if bsd_name:
            self.block_button.configure(state="normal")
        else:
            self.block_button.configure(state="disabled")
            logging.warning("No BSD Name available, eject disabled")

    def eject_device(self):
        if self.unauthorized_device:
            vendor_id, product_id, bsd_name = self.unauthorized_device
            if platform.system() == "Darwin" and bsd_name:
                try:
                    subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True)
                    messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} ejected.")
                    self.unauthorized_device = None
                    self.block_button.configure(state="disabled")
                    self.alert_frame.pack_forget()
                    self.update_gui()
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Failed to eject device: {e}. Requires admin privileges.")
                    logging.error(f"Eject error: {e}")
            else:
                messagebox.showwarning("Warning", "Eject not supported on this system or device not identified.")
                logging.warning(f"Eject not supported for {vendor_id}:{product_id}")
            self.update_gui()

    def on_device_select(self, event):
        try:
            selection = self.device_listbox.curselection()
            if selection:
                self.selected_device = self.device_listbox.get(selection[0])
                self.status_label.configure(text=f"Selected: {self.selected_device}")
                logging.info(f"Device selected: {self.selected_device}")
            else:
                self.selected_device = None
                self.status_label.configure(text="Monitoring USB devices...")
        except Exception as e:
            logging.error(f"Error in on_device_select: {e}")

    def remove_from_whitelist(self):
        try:
            if not self.selected_device:
                messagebox.showwarning("Warning", "Please select a device to remove from whitelist.")
                return
            vendor_id, product_id = self.selected_device.split(" - ")[0].split(":")
            if not is_device_whitelisted(vendor_id, product_id):
                messagebox.showwarning("Warning", f"Device {vendor_id}:{product_id} is not whitelisted.")
                return
            remove_from_whitelist(vendor_id, product_id)
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} removed from whitelist.")
            self.update_gui()
        except Exception as e:
            logging.error(f"Remove from whitelist error: {e}")
            messagebox.showerror("Error", str(e))

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            self.device_listbox.delete(0, END)

            unauthorized_detected = False
            self.devices = current_devices  # Zawsze aktualizujemy self.devices
            for i, (vendor_id, product_id, *_) in enumerate(sorted(self.devices)):
                status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                entry = f"{vendor_id}:{product_id} - {status}"
                self.device_listbox.insert(END, entry)
                self.device_listbox.itemconfig(i, fg="#55FF55" if status == "Authorized" else "#FF5555")
                if status == "Unauthorized":
                    unauthorized_detected = True
                self.progress.set((i + 1) / max(len(self.devices), 1))

            if not unauthorized_detected and self.unauthorized_device:
                self.unauthorized_device = None
                self.block_button.configure(state="disabled")
                self.alert_frame.pack_forget()

            self.whitelist_listbox.delete("0.0", "end")
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT vendor_id, product_id FROM whitelist")
            for vid, pid in c.fetchall():
                self.whitelist_listbox.insert("end", f"{vid}:{pid}\n")
            conn.close()

            self.log_text.delete("0.0", "end")
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    self.log_text.insert("end", f.read())
                self.log_text.see("end")

            self.progress.set(1)
        except Exception as e:
            logging.error(f"GUI update error: {e}")
            self.status_label.configure(text=f"Error: {e}", text_color="#FF5555")

        self.after(5000, self.update_gui)

    def check_alert_queue(self):
        while not alert_queue.empty():
            vendor_id, product_id, bsd_name = alert_queue.get()
            self.alert_unauthorized(vendor_id, product_id, bsd_name)
        self.after(100, self.check_alert_queue)

    def add_to_whitelist(self):
        try:
            if not self.selected_device:
                messagebox.showwarning("Warning", "Please select a device to whitelist.")
                return
            vendor_id, product_id = self.selected_device.split(" - ")[0].split(":")
            add_to_whitelist(vendor_id, product_id)
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added.")
            self.update_gui()
        except Exception as e:
            logging.error(f"Add to whitelist error: {e}")
            messagebox.showerror("Error", str(e))

    def export_logs_csv(self):
        try:
            if not os.path.exists(LOG_FILE):
                messagebox.showwarning("Warning", "No logs to export.")
                return
            with open(LOG_FILE, "r") as f:
                logs = f.readlines()
            with open(f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Log Entry"])
                for log in logs:
                    writer.writerow([log.strip()])
            messagebox.showinfo("Success", "Logs exported to CSV.")
        except Exception as e:
            logging.error(f"Export CSV error: {e}")
            messagebox.showerror("Error", str(e))

    def export_logs_json(self):
        try:
            if not os.path.exists(LOG_FILE):
                messagebox.showwarning("Warning", "No logs to export.")
                return
            with open(LOG_FILE, "r") as f:
                logs = f.readlines()
            log_data = [{"entry": log.strip()} for log in logs]
            with open(f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
                json.dump(log_data, f, indent=4)
            messagebox.showinfo("Success", "Logs exported to JSON.")
        except Exception as e:
            logging.error(f"Export JSON error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = USBMonitorApp()
    app.mainloop()