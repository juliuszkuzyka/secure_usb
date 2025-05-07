import customtkinter as ctk
import logging
import os
import sqlite3
from threading import Thread
from tkinter import messagebox
import csv
import json
from datetime import datetime

from .usb_monitor import get_connected_devices, monitor_usb
from .database import is_device_whitelisted, add_to_whitelist
from config import LOG_FILE, DB_FILE

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("USB Security Monitor")
        self.geometry("1300x1000")
        self.configure(fg_color="#1A1A1A")  # Jednolite tło
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.devices = set()
        self.selected_device = None
        self.setup_ui()
        Thread(target=monitor_usb, daemon=True).start()
        self.update_gui()

    def setup_ui(self):
        # Header
        self.header_label = ctk.CTkLabel(self, text="USB Security Monitor", font=("Segoe UI", 24, "bold"), text_color="#FFFFFF")
        self.header_label.pack(pady=15)

        # Device Frame
        self.device_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.device_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.device_label = ctk.CTkLabel(self.device_frame, text="Connected USB Devices", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.device_label.pack(pady=5)

        self.device_listbox = ctk.CTkScrollableFrame(self.device_frame, height=150, width=700, fg_color="#2D2D2D", corner_radius=10)
        self.device_listbox.pack(pady=5)
        self.device_labels = []

        # Whitelist Frame
        self.whitelist_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.whitelist_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.whitelist_label = ctk.CTkLabel(self.whitelist_frame, text="Whitelisted Devices", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.whitelist_label.pack(pady=5)

        self.whitelist_listbox = ctk.CTkTextbox(self.whitelist_frame, height=100, width=700, font=("Segoe UI", 13), corner_radius=10, fg_color="#2D2D2D", text_color="#D4D4D4")
        self.whitelist_listbox.pack(pady=5)

        # Buttons Frame
        self.buttons_frame = ctk.CTkFrame(self, fg_color="#1A1A1A")
        self.buttons_frame.pack(pady=10, side="top")
        self.add_button = ctk.CTkButton(self.buttons_frame, text="Add to Whitelist", command=self.add_to_whitelist, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 12), corner_radius=8)
        self.add_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(self.buttons_frame, text="Refresh", command=self.update_gui, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 12), corner_radius=8)
        self.refresh_button.pack(side="left", padx=5)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self, width=700, progress_color="#4A90E2")
        self.progress.set(0)
        self.progress.pack(pady=5)

        # Log Frame with Tabs
        self.log_frame = ctk.CTkFrame(self, fg_color="#252526")
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5, side="top")
        self.log_label = ctk.CTkLabel(self.log_frame, text="Recent Events", font=("Segoe UI", 16, "bold"), text_color="#D4D4D4")
        self.log_label.pack(pady=5)

        self.tabview = ctk.CTkTabview(self.log_frame, fg_color="#2D2D2D", segmented_button_fg_color="#357ABD", segmented_button_selected_color="#4A90E2")
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)
        self.tabview.add("Logs")
        self.tabview.add("Export")

        # Logs Tab
        self.log_text = ctk.CTkTextbox(self.tabview.tab("Logs"), height=150, width=700, font=("Consolas", 13), corner_radius=10, fg_color="#2D2D2D", text_color="#D4D4D4")
        self.log_text.pack(pady=5)

        # Export Tab
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2D2D2D")
        self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkButton(self.export_frame, text="Export CSV", command=self.export_logs_csv, fg_color="#4A90E2", hover_color="#2A5C99", font=("Segoe UI", 12), corner_radius=8).pack(pady=5)
        ctk.CTkButton(self.export_frame, text="Export JSON", command=self.export_logs_json, fg_color="#357ABD", hover_color="#1E3A5F", font=("Segoe UI", 12), corner_radius=8).pack(pady=5)

        # Status Bar
        self.status_label = ctk.CTkLabel(self, text="Monitoring USB devices...", font=("Segoe UI", 13), text_color="#A0A0A0")
        self.status_label.pack(side="bottom", pady=5)

        # Alert Frame
        self.alert_frame = ctk.CTkFrame(self, fg_color="#1A1A1A")
        self.alert_label = ctk.CTkLabel(self.alert_frame, text="", font=("Segoe UI", 14, "bold"), text_color="#FF5555")
        self.alert_label.pack(pady=5)

    def on_device_select(self, event):
        try:
            widget = event.widget.winfo_containing(event.x_root, event.y_root)
            if widget and isinstance(widget, ctk.CTkLabel):
                self.selected_device = widget.cget("text")
                self.status_label.configure(text=f"Selected: {self.selected_device}")
        except Exception as e:
            logging.error(f"Error in on_device_select: {e}")

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            if current_devices != self.devices:
                self.devices = current_devices
                for label in self.device_labels:
                    label.destroy()
                self.device_labels.clear()

                unauthorized_detected = False
                for i, (vendor_id, product_id) in enumerate(sorted(self.devices)):
                    status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                    color = "#55FF55" if status == "Authorized" else "#FF5555"
                    entry = f"{vendor_id}:{product_id} - {status}"
                    label = ctk.CTkLabel(self.device_listbox, text=entry, font=("Segoe UI", 13), text_color=color, anchor="w")
                    label.pack(fill="x", padx=5, pady=2)
                    label.bind("<Button-1>", self.on_device_select)
                    self.device_labels.append(label)
                    if status == "Unauthorized":
                        unauthorized_detected = True
                    self.progress.set((i + 1) / len(self.devices))

                if unauthorized_detected:
                    self.alert_frame.pack(pady=5)
                    self.alert_label.configure(text="Unauthorized Device Detected!")
                    self.alert_frame.lift()
                else:
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