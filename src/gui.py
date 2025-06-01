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
from config import LOG_FILE, DB_FILE

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            filemode='w',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info("[INIT] Starting USBMonitorApp")
        self.title("USB Security Monitor")
        self.geometry("1400x900")
        self.configure(fg_color="#121212")
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
        logging.info("[INIT] Setting up UI")
        # Main frame
        self.main_frame = ctk.CTkFrame(self, fg_color="#121212", corner_radius=0)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E1E1E", corner_radius=8)
        self.header_frame.pack(fill="x", pady=(0, 10))
        self.header_label = ctk.CTkLabel(
            self.header_frame,
            text="🔒 USB Security Monitor",
            font=("Roboto", 24, "bold"),
            text_color="#FFFFFF"
        )
        self.header_label.pack(side="left", padx=10, pady=10)
        self.status_label = ctk.CTkLabel(
            self.header_frame,
            text="Monitoring... 🔍",
            font=("Roboto", 14),
            text_color="#B0BEC5"
        )
        self.status_label.pack(side="right", padx=10)

        # Content area
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="#121212")
        self.content_frame.pack(fill="both", expand=True)
        self.content_frame.grid_columnconfigure((0, 1), weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Left panel (Devices and Whitelist)
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="#1E1E1E", corner_radius=8)
        self.left_frame.grid(row=0, column=0, padx=(0, 5), pady=0, sticky="nsew")
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure((1, 3), weight=1)

        self.device_label = ctk.CTkLabel(
            self.left_frame,
            text="📟 Connected Devices",
            font=("Roboto", 16, "bold"),
            text_color="#FFFFFF"
        )
        self.device_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")

        self.device_textbox = Text(
            self.left_frame,
            height=6,
            font=("Roboto", 12),
            bg="#2A2A2A",
            fg="#CFD8DC",
            insertbackground="#CFD8DC",
            wrap="none",
            cursor="hand2",
            borderwidth=0,
            relief="flat"
        )
        self.device_textbox.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="nsew")
        self.device_textbox.bind("<Button-1>", self.on_device_select)

        self.whitelist_label = ctk.CTkLabel(
            self.left_frame,
            text="✅ Whitelisted Devices",
            font=("Roboto", 16, "bold"),
            text_color="#FFFFFF"
        )
        self.whitelist_label.grid(row=2, column=0, pady=(5, 5), padx=10, sticky="w")

        self.whitelist_textbox = Text(
            self.left_frame,
            height=6,
            font=("Roboto", 12),
            bg="#2A2A2A",
            fg="#CFD8DC",
            insertbackground="#CFD8DC",
            wrap="none",
            cursor="hand2",
            borderwidth=0,
            relief="flat"
        )
        self.whitelist_textbox.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.whitelist_textbox.bind("<Button-1>", self.on_whitelist_select)

        # Right panel (Tabs)
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color="#1E1E1E", corner_radius=8)
        self.right_frame.grid(row=0, column=1, padx=(5, 0), pady=0, sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)

        self.tabview = ctk.CTkTabview(
            self.right_frame,
            fg_color="#2A2A2A",
            segmented_button_fg_color="#0288D1",
            segmented_button_selected_color="#03A9F4",
            segmented_button_selected_hover_color="#81D4FA",
            text_color="#FFFFFF",
            corner_radius=6,
            height=450
        )
        self.tabview.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="nsew")
        self.tabview.add("Dashboard")
        self.tabview.add("Logs")
        self.tabview.add("Export")
        self.tabview.set("Dashboard")

        # Dashboard tab
        self.dashboard_frame = ctk.CTkFrame(self.tabview.tab("Dashboard"), fg_color="#2A2A2A", corner_radius=6)
        self.dashboard_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.alert_frame = ctk.CTkFrame(self.dashboard_frame, fg_color="#2A2A2A")
        self.alert_label = ctk.CTkLabel(
            self.alert_frame,
            text="",
            font=("Roboto", 14, "bold"),
            text_color="#D32F2F"
        )
        self.alert_label.pack(pady=5)
        self.progress = ctk.CTkProgressBar(
            self.dashboard_frame,
            width=400,
            height=8,
            progress_color="#0288D1",
            fg_color="#424242",
            border_width=0
        )
        self.progress.set(0)
        self.progress.pack(pady=10)

        # Logs tab
        self.log_text = ctk.CTkTextbox(
            self.tabview.tab("Logs"),
            height=250,
            font=("Consolas", 11),
            corner_radius=6,
            fg_color="#2A2A2A",
            text_color="#CFD8DC",
            wrap="none",
            border_width=0
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Export tab
        self.export_frame = ctk.CTkFrame(self.tabview.tab("Export"), fg_color="#2A2A2A", corner_radius=6)
        self.export_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkButton(
            self.export_frame,
            text="Export CSV 📄",
            command=self.export_logs_csv,
            fg_color="#0288D1",
            hover_color="#01579B",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            height=32
        ).pack(pady=6)
        ctk.CTkButton(
            self.export_frame,
            text="Export JSON 📋",
            command=self.export_logs_json,
            fg_color="#0277BD",
            hover_color="#01477B",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            height=32
        ).pack(pady=6)

        # Bottom action bar
        self.action_frame = ctk.CTkFrame(self.main_frame, fg_color="#1E1E1E", corner_radius=8)
        self.action_frame.pack(side="bottom", fill="x", pady=(10, 0))
        self.add_button = ctk.CTkButton(
            self.action_frame,
            text="Add to Whitelist ➕",
            command=self.add_to_whitelist,
            fg_color="#4CAF50",
            hover_color="#388E3C",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            width=160,
            height=32
        )
        self.add_button.pack(side="left", padx=5)
        self.remove_button = ctk.CTkButton(
            self.action_frame,
            text="Remove from Whitelist ➖",
            command=self.remove_from_whitelist,
            fg_color="#D32F2F",
            hover_color="#B71C1C",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            width=160,
            height=32
        )
        self.remove_button.pack(side="left", padx=5)
        self.refresh_button = ctk.CTkButton(
            self.action_frame,
            text="Refresh 🔄",
            command=self.update_gui,
            fg_color="#0288D1",
            hover_color="#01579B",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            width=160,
            height=32
        )
        self.refresh_button.pack(side="left", padx=5)
        self.block_button = ctk.CTkButton(
            self.action_frame,
            text="Eject Unauthorized 🚫",
            command=self.eject_device,
            fg_color="#D32F2F",
            hover_color="#B71C1C",
            font=("Roboto", 12, "bold"),
            corner_radius=6,
            width=160,
            height=32
        )
        self.block_button.pack(side="left", padx=5)

    def on_device_select(self, event):
        try:
            cursor_pos = self.device_textbox.index("current")
            line_num = int(float(cursor_pos))
            lines = self.device_textbox.get("1.0", "end").splitlines()
            if 1 <= line_num <= len(lines):
                line = lines[line_num - 1].strip()
                device_id = line.split(" - ")[0].split(" ", 1)[-1]
                self.selected_device = device_id
                self.device_textbox.tag_remove("selected", "1.0", END)
                self.device_textbox.tag_add("selected", f"{line_num}.0", f"{line_num}.end")
                self.device_textbox.tag_configure("selected", background="#0288D1", foreground="#FFFFFF")
                self.whitelist_textbox.tag_remove("selected", "1.0", END)
                self.status_label.configure(text=f"Selected: {self.selected_device}")
                logging.info(f"[ACTION] Selected from Connected Devices: {self.selected_device}")
            else:
                self.selected_device = None
                self.device_textbox.tag_remove("selected", "1.0", END)
                self.whitelist_textbox.tag_remove("selected", "1.0", END)
                self.status_label.configure(text="Monitoring USB devices... 🔍")
                logging.info("[ACTION] Selection cleared")
        except Exception as e:
            logging.error(f"[ACTION] Device selection error: {e}")
            self.selected_device = None
            self.device_textbox.tag_remove("selected", "1.0", END)
            self.whitelist_textbox.tag_remove("selected", "1.0", END)
            self.status_label.configure(text=f"Error: {e}", text_color="#D32F2F")

    def on_whitelist_select(self, event):
        try:
            cursor_pos = self.whitelist_textbox.index("current")
            line_num = int(float(cursor_pos))
            lines = self.whitelist_textbox.get("1.0", "end").splitlines()
            if 1 <= line_num <= len(lines):
                line = lines[line_num - 1].strip()
                device_id = line.split(" ", 1)[-1]
                self.selected_device = device_id
                self.whitelist_textbox.tag_remove("selected", "1.0", END)
                self.whitelist_textbox.tag_add("selected", f"{line_num}.0", f"{line_num}.end")
                self.whitelist_textbox.tag_configure("selected", background="#0288D1", foreground="#FFFFFF")
                self.device_textbox.tag_remove("selected", "1.0", END)
                self.status_label.configure(text=f"Selected: {self.selected_device}")
                logging.info(f"[ACTION] Selected from Whitelist: {self.selected_device}")
            else:
                self.selected_device = None
                self.device_textbox.tag_remove("selected", "1.0", END)
                self.whitelist_textbox.tag_remove("selected", "1.0", END)
                self.status_label.configure(text="Monitoring USB devices... 🔍")
                logging.info("[ACTION] Selection cleared")
        except Exception as e:
            logging.error(f"[ACTION] Whitelist selection error: {e}")
            self.selected_device = None
            self.device_textbox.tag_remove("selected", "1.0", END)
            self.whitelist_textbox.tag_remove("selected", "1.0", END)
            self.status_label.configure(text=f"Error: {e}", text_color="#D32F2F")

    def process_alert(self, vendor_id, product_id, bsd_name):
        self.after(0, lambda: self.alert_unauthorized(vendor_id, product_id, bsd_name))

    def alert_unauthorized(self, vendor_id, product_id, bsd_name=None):
        self.unauthorized_device = (vendor_id, product_id, bsd_name)
        self.alert_label.configure(text=f"⚠️ Unauthorized Device: {vendor_id}:{product_id}")
        self.alert_frame.pack(pady=5)
        self.alert_frame.lift()
        logging.info(f"[ALERT] Unauthorized device: {vendor_id}:{product_id}")
        if not bsd_name:
            logging.warning(f"[BLOCK] Cannot eject {vendor_id}:{product_id}: No BSD Name")

    def eject_device(self):
        if self.unauthorized_device:
            vendor_id, product_id, bsd_name = self.unauthorized_device
            if platform.system() == "Darwin":
                if bsd_name:
                    try:
                        subprocess.run(["diskutil", "eject", f"/dev/{bsd_name}"], check=True)
                        logging.info(f"[BLOCK] Ejected {vendor_id}:{product_id}")
                        messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} ejected.")
                        self.unauthorized_device = None
                        self.alert_frame.pack_forget()
                    except subprocess.CalledProcessError as e:
                        logging.error(f"[BLOCK] Eject failed for {vendor_id}:{product_id}: {e}")
                        messagebox.showerror("Error", f"Failed to eject device: {e}. Requires admin privileges.")
                else:
                    logging.warning(f"[BLOCK] Cannot eject {vendor_id}:{product_id}: No BSD Name")
                    messagebox.showwarning("Warning", "Cannot eject: Device not identified (no BSD Name).")
            else:
                logging.warning(f"[BLOCK] Eject not supported for {vendor_id}:{product_id}")
                messagebox.showwarning("Warning", "Eject not supported on this system.")
            self.update_gui()
        else:
            logging.info("[ACTION] No unauthorized device to eject")
            messagebox.showinfo("Info", "No unauthorized device to eject.")

    def remove_from_whitelist(self):
        try:
            if not self.selected_device:
                messagebox.showwarning("Warning", "Please select a device to remove from whitelist.")
                return
            vendor_id, product_id = self.selected_device.split(":")
            if not is_device_whitelisted(vendor_id, product_id):
                messagebox.showwarning("Warning", f"Device {vendor_id}:{product_id} is not whitelisted.")
                return
            remove_from_whitelist(vendor_id, product_id)
            logging.info(f"[WHITELIST] Removed: {vendor_id}:{product_id}")
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} removed from whitelist.")
            for dev_vendor_id, dev_product_id, bsd_name in self.devices:
                if dev_vendor_id == vendor_id and dev_product_id == product_id:
                    if not is_device_whitelisted(vendor_id, product_id):
                        self.alert_unauthorized(vendor_id, product_id, bsd_name)
                        break
            self.update_gui()
        except Exception as e:
            logging.error(f"[WHITELIST] Remove error: {e}")
            messagebox.showerror("Error", str(e))

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            self.device_textbox.delete("1.0", END)
            self.whitelist_textbox.delete("1.0", END)

            unauthorized_detected = False
            self.devices = current_devices
            for i, (vendor_id, product_id, *_) in enumerate(sorted(self.devices)):
                status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                icon = "✅ " if status == "Authorized" else "❌ "
                entry = f"{icon}{vendor_id}:{product_id} - {status}\n"
                self.device_textbox.insert(END, entry)
                self.device_textbox.tag_add(status, f"{i+1}.0", f"{i+1}.end")
                self.device_textbox.tag_configure("Authorized", foreground="#4CAF50")
                self.device_textbox.tag_configure("Unauthorized", foreground="#D32F2F")
                if status == "Unauthorized":
                    unauthorized_detected = True
                self.progress.set((i + 1) / max(len(self.devices), 1))

            if not unauthorized_detected and self.unauthorized_device:
                self.unauthorized_device = None
                self.alert_frame.pack_forget()

            try:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("SELECT vendor_id, product_id FROM whitelist")
                for i, (vid, pid) in enumerate(c.fetchall()):
                    entry = f"✔️ {vid}:{pid}\n"
                    self.whitelist_textbox.insert(END, entry)
                    self.whitelist_textbox.tag_add("Whitelisted", f"{i+1}.0", f"{i+1}.end")
                    self.whitelist_textbox.tag_configure("Whitelisted", foreground="#4CAF50")
                conn.close()
            except sqlite3.Error as e:
                logging.error(f"[WHITELIST] Fetch error: {e}")

            self.log_text.delete("1.0", END)
            try:
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r") as f:
                        self.log_text.insert(END, f.read())
                    self.log_text.see(END)
                    logging.debug("[GUI] Logs loaded")
                else:
                    logging.warning(f"[GUI] Log file {LOG_FILE} not found")
                    self.log_text.insert(END, "Log file not found\n")
            except Exception as e:
                logging.error(f"[GUI] Log load error: {e}")
                self.log_text.insert(END, f"Error loading logs: {e}\n")

        except Exception as e:
            logging.error(f"[GUI] Update error: {e}")
            self.status_label.configure(text=f"Error: {e}", text_color="#D32F2F")

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
            vendor_id, product_id = self.selected_device.split(":")
            add_to_whitelist(vendor_id, product_id)
            logging.info(f"[WHITELIST] Added: {vendor_id}:{product_id}")
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added.")
            self.update_gui()
        except Exception as e:
            logging.error(f"[WHITELIST] Add error: {e}")
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
            logging.info("[ACTION] Exported to CSV")
            messagebox.showinfo("Success", "Logs exported to CSV.")
        except Exception as e:
            logging.error(f"[ACTION] CSV export error: {e}")
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
            logging.info("[ACTION] Exported to JSON")
            messagebox.showinfo("Success", "Logs exported to JSON.")
        except Exception as e:
            logging.error(f"[ACTION] JSON export error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = USBMonitorApp()
    app.mainloop()
    logging.info("[INIT] Application closed")