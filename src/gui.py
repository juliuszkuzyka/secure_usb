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
from queue import Queue

from .usb_monitor import get_connected_devices, monitor_usb, set_alert_callback, alert_queue
from .database import is_device_whitelisted, add_to_whitelist, remove_from_whitelist
from config import LOG_FILE, DB_FILE

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        logging.basicConfig(filename="logs/events.log", level=logging.DEBUG, filemode='w')
        logging.info("Initializing USBMonitorApp")
        self.title("USB Security Monitor")
        self.geometry("1400x900")
        self.configure(fg_color="#0D1B2A")  # Ciemne tło z nutą granatu
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
        logging.info("Setting up UI")
        # Główny kontener
        self.main_frame = ctk.CTkFrame(self, fg_color="#0D1B2A", corner_radius=0)
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Nagłówek z gradientem
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="#1B263B", corner_radius=10, border_width=1, border_color="#415A77")
        self.header_frame.pack(fill="x", pady=(0, 10))
        self.header_label = ctk.CTkLabel(
            self.header_frame,
            text="🔒 USB Security Monitor",
            font=("Segoe UI", 28, "bold"),
            text_color="#E0E1DD",
            anchor="w"
        )
        self.header_label.pack(pady=10, padx=15)

        # Główna sekcja z grid
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure((0, 1), weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Lewa sekcja: Urządzenia i Whitelist
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="#1B263B", corner_radius=10)
        self.left_frame.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="nsew")
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=1)

        # Sekcja urządzeń
        self.device_label = ctk.CTkLabel(
            self.left_frame,
            text="📟 Connected USB Devices",
            font=("Segoe UI", 18, "bold"),
            text_color="#E0E1DD"
        )
        self.device_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")

        self.device_textbox = ctk.CTkTextbox(
            self.left_frame,
            height=200,
            font=("Segoe UI", 14),
            fg_color="#2D2D2D",
            text_color="#D4D4D4",
            corner_radius=8,
            wrap="none"
        )
        self.device_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        # Sekcja whitelist
        self.whitelist_label = ctk.CTkLabel(
            self.left_frame,
            text="✅ Whitelisted Devices",
            font=("Segoe UI", 18, "bold"),
            text_color="#E0E1DD"
        )
        self.whitelist_label.grid(row=2, column=0, pady=(10, 5), padx=10, sticky="w")

        self.whitelist_textbox = ctk.CTkTextbox(
            self.left_frame,
            height=200,
            font=("Segoe UI", 14),
            fg_color="#2D2D2D",
            text_color="#D4D4D4",
            corner_radius=8,
            wrap="none"
        )
        self.whitelist_textbox.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")

        # Prawa sekcja: Logi i eksport
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="#1B263B", corner_radius=10)
        self.right_frame.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)

        self.log_label = ctk.CTkLabel(
            self.right_frame,
            text="📜 Recent Events",
            font=("Segoe UI", 18, "bold"),
            text_color="#E0E1DD"
        )
        self.log_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")

        self.tabview = ctk.CTkTabview(
            self.right_frame,
            fg_color="#2D2D2D",
            segmented_button_fg_color="#415A77",
            segmented_button_selected_color="#778DA9",
            segmented_button_selected_hover_color="#E0E1DD",
            text_color="#E0E1DD"
        )
        self.tabview.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.tabview.add("Logs")
        self.tabview.add("Export")

        self.log_text = ctk.CTkTextbox(
            self.tabview.tab("Logs"),
            height=400,
            font=("Consolas", 13),
            corner_radius=8,
            fg_color="#2D2D2D",
            text_color="#D4D4D4",
            wrap="none"
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2D2D2D")
        self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkButton(
            self.export_frame,
            text="Export CSV 📄",
            command=self.export_logs_csv,
            fg_color="#4A90E2",
            hover_color="#2A5C99",
            font=("Segoe UI", 14),
            corner_radius=8
        ).pack(pady=10)
        ctk.CTkButton(
            self.export_frame,
            text="Export JSON 📋",
            command=self.export_logs_json,
            fg_color="#357ABD",
            hover_color="#1E3A5F",
            font=("Segoe UI", 14),
            corner_radius=8
        ).pack(pady=10)

        # Przyciski akcji
        self.buttons_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.buttons_frame.pack(fill="x", pady=10)
        self.add_button = ctk.CTkButton(
            self.buttons_frame,
            text="Add to Whitelist ➕",
            command=self.add_to_whitelist,
            fg_color="#2ECC71",
            hover_color="#27AE60",
            font=("Segoe UI", 14),
            corner_radius=8,
            width=200
        )
        self.add_button.pack(side="left", padx=5)
        self.remove_button = ctk.CTkButton(
            self.buttons_frame,
            text="Remove from Whitelist ➖",
            command=self.remove_from_whitelist,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            font=("Segoe UI", 14),
            corner_radius=8,
            width=200
        )
        self.remove_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(
            self.buttons_frame,
            text="Refresh 🔄",
            command=self.update_gui,
            fg_color="#3498DB",
            hover_color="#2980B9",
            font=("Segoe UI", 14),
            corner_radius=8,
            width=200
        )
        self.refresh_button.pack(side="left", padx=5)

        # Sekcja eject
        self.block_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.block_frame.pack(fill="x", pady=5)
        self.block_button = ctk.CTkButton(
            self.block_frame,
            text="Eject Unauthorized Device 🚫",
            command=self.eject_device,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            font=("Segoe UI", 14),
            corner_radius=8,
            state="disabled",
            width=300
        )
        self.block_button.pack(pady=5)

        # Pasek postępu
        self.progress = ctk.CTkProgressBar(self.main_frame, width=700, progress_color="#3498DB", fg_color="#2D2D2D")
        self.progress.set(0)
        self.progress.pack(pady=10)

        # Status i alert
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color="#0D1B2A")
        self.status_frame.pack(fill="x", pady=5)
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Monitoring USB devices... 🔍",
            font=("Segoe UI", 14),
            text_color="#A0A0A0"
        )
        self.status_label.pack(side="bottom")

        self.alert_frame = ctk.CTkFrame(self.status_frame, fg_color="#0D1B2A")
        self.alert_label = ctk.CTkLabel(
            self.alert_frame,
            text="",
            font=("Segoe UI", 16, "bold"),
            text_color="#E74C3C"
        )
        self.alert_label.pack(pady=5)

    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, lambda: self.alert_unauthorized(vendor_id, product_id, bsd_name))

    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"⚠️ Unauthorized Device Detected: {vendor_id}:{product_id}")
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
            # Pobierz wybraną linię z textbox
            cursor_pos = self.device_textbox.index("current")
            line_num = int(float(cursor_pos))
            lines = self.device_textbox.get("1.0", "end").splitlines()
            if 1 <= line_num <= len(lines):
                self.selected_device = lines[line_num - 1].strip()
                self.status_label.configure(text=f"Selected: {self.selected_device}")
                logging.info(f"Device selected: {self.selected_device}")
            else:
                self.selected_device = None
                self.status_label.configure(text="Monitoring USB devices... 🔍")
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
            logging.info("Updating GUI")
            current_devices = get_connected_devices()
            self.device_textbox.delete("1.0", END)

            unauthorized_detected = False
            self.devices = current_devices
            for i, (vendor_id, product_id, *_) in enumerate(sorted(self.devices)):
                status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                icon = "✅ " if status == "Authorized" else "❌ "
                entry = f"{icon}{vendor_id}:{product_id} - {status}\n"
                self.device_textbox.insert(END, entry)
                self.device_textbox.tag_add(status, f"{i+1}.0", f"{i+1}.end")
                self.device_textbox.tag_configure("Authorized", foreground="#2ECC71")
                self.device_textbox.tag_configure("Unauthorized", foreground="#E74C3C")
                if status == "Unauthorized":
                    unauthorized_detected = True
                self.progress.set((i + 1) / max(len(self.devices), 1))

            if not unauthorized_detected and self.unauthorized_device:
                self.unauthorized_device = None
                self.block_button.configure(state="disabled")
                self.alert_frame.pack_forget()

            self.whitelist_textbox.delete("1.0", END)
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT vendor_id, product_id FROM whitelist")
            for vid, pid in c.fetchall():
                self.whitelist_textbox.insert(END, f"✔️ {vid}:{pid}\n")
            conn.close()

            self.log_text.delete("1.0", END)
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    self.log_text.insert(END, f.read())
                self.log_text.see(END)

            self.progress.set(1)
            logging.info("GUI update completed")
        except Exception as e:
            logging.error(f"GUI update error: {e}")
            self.status_label.configure(text=f"Error: {e}", text_color="#E74C3C")

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
            vendor_id, product_id = self.selected_device.split(" - ")[0].split(":")[1:]
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
    logging.info("Application closed")