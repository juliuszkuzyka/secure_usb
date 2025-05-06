import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
import logging
import os

from .usb_monitor import get_connected_devices, monitor_usb
from .database import is_device_whitelisted, add_to_whitelist
from config import LOG_FILE, DB_FILE

class USBMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Security Monitor")
        self.root.geometry("900x600")
        self.root.configure(bg="#2E2E2E")
        self.devices = set()

        self.setup_widgets()
        Thread(target=monitor_usb, daemon=True).start()
        self.update_gui()

    def setup_widgets(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", foreground="white", background="#2E2E2E")
        style.configure("TButton", background="#4A90E2", foreground="white")

        self.device_frame = ttk.LabelFrame(self.root, text="Connected USB Devices")
        self.device_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.device_list = tk.Listbox(self.device_frame, height=10, bg="#3C3F41", fg="white")
        self.device_list.pack(fill="both", padx=5, pady=5)
        self.device_list.bind('<<ListboxSelect>>', self.on_device_select)

        self.device_buttons = ttk.Frame(self.device_frame)
        self.device_buttons.pack(pady=5)
        ttk.Button(self.device_buttons, text="Add to Whitelist", command=self.add_to_whitelist).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.device_buttons, text="Refresh", command=self.update_gui).pack(side=tk.LEFT, padx=5)

        self.whitelist_frame = ttk.LabelFrame(self.root, text="Whitelisted Devices")
        self.whitelist_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.whitelist_list = tk.Listbox(self.whitelist_frame, height=5, bg="#3C3F41", fg="white")
        self.whitelist_list.pack(fill="both", padx=5, pady=5)

        self.log_frame = ttk.LabelFrame(self.root, text="Recent Events")
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(self.log_frame, height=5, bg="#3C3F41", fg="white", state='disabled')
        self.log_text.pack(fill="both", padx=5, pady=5)

        self.status_var = tk.StringVar(value="Monitoring USB devices...")
        self.status_label = ttk.Label(self.root, textvariable=self.status_var)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

    def on_device_select(self, event):
        try:
            selected = self.device_list.get(tk.ACTIVE)
            if selected:
                self.status_var.set(f"Selected: {selected}")
        except Exception as e:
            logging.error(f"Device select error: {e}")

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            if current_devices != self.devices:
                self.devices = current_devices
                self.device_list.delete(0, tk.END)
                for vendor_id, product_id in self.devices:
                    status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                    self.device_list.insert(tk.END, f"{vendor_id}:{product_id} - {status}")

            self.whitelist_list.delete(0, tk.END)
            import sqlite3
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT vendor_id, product_id FROM whitelist")
            for vid, pid in c.fetchall():
                self.whitelist_list.insert(tk.END, f"{vid}:{pid}")
            conn.close()

            self.log_text.configure(state='normal')
            self.log_text.delete(1.0, tk.END)
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    lines = f.readlines()[-10:]
                    for line in lines:
                        self.log_text.insert(tk.END, line)
            self.log_text.configure(state='disabled')

        except Exception as e:
            logging.error(f"GUI update error: {e}")
            self.status_var.set(f"Error: {e}")
        self.root.after(2000, self.update_gui)

    def add_to_whitelist(self):
        try:
            if not self.device_list.curselection():
                messagebox.showwarning("Warning", "Please select a device to whitelist.")
                return
            selected = self.device_list.get(tk.ACTIVE)
            vendor_id, product_id = selected.split(" - ")[0].split(":")
            add_to_whitelist(vendor_id, product_id)
            self.status_var.set(f"Added {vendor_id}:{product_id} to whitelist")
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added.")
            self.update_gui()
        except Exception as e:
            logging.error(f"Add to whitelist error: {e}")
            messagebox.showerror("Error", str(e))
