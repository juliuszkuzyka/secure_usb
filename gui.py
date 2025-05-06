import tkinter as tk
from tkinter import messagebox
from threading import Thread
import logging
from usb_monitor import get_connected_devices, monitor_usb
from database import add_to_whitelist, is_device_whitelisted
from datetime import datetime

class USBMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Security Monitor")
        self.root.geometry("800x600")
        self.devices = set()

        # Device List Frame
        self.device_frame = tk.LabelFrame(root, text="Connected USB Devices", font=("Arial", 12))
        self.device_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.device_list = tk.Listbox(self.device_frame, width=60, height=10, font=("Arial", 10))
        self.device_list.pack(pady=5, padx=5)
        self.device_list.bind('<<ListboxSelect>>', self.on_device_select)

        # Device Buttons
        self.device_buttons = tk.Frame(self.device_frame)
        self.device_buttons.pack(pady=5)
        tk.Button(self.device_buttons, text="Add to Whitelist", command=self.add_to_whitelist).pack(side=tk.LEFT, padx=5)
        tk.Button(self.device_buttons, text="Refresh", command=self.update_gui).pack(side=tk.LEFT, padx=5)

        # Whitelist Frame
        self.whitelist_frame = tk.LabelFrame(root, text="Whitelisted Devices", font=("Arial", 12))
        self.whitelist_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.whitelist_list = tk.Listbox(self.whitelist_frame, width=60, height=5, font=("Arial", 10))
        self.whitelist_list.pack(pady=5, padx=5)

        # Log Frame
        self.log_frame = tk.LabelFrame(root, text="Recent Events", font=("Arial", 12))
        self.log_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.log_text = tk.Text(self.log_frame, width=60, height=5, font=("Arial", 10), state='disabled')
        self.log_text.pack(pady=5, padx=5)

        # Status Bar
        self.status_var = tk.StringVar(value="Monitoring USB devices...")
        self.status_label = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Start monitoring in a separate thread
        self.monitor_thread = Thread(target=monitor_usb, daemon=True)
        self.monitor_thread.start()

        # Initial update
        self.update_gui()

    def on_device_select(self, event):
        """Update status bar with selected device info."""
        try:
            selected = self.device_list.get(tk.ACTIVE)
            if selected:
                self.status_var.set(f"Selected: {selected}")
        except:
            pass

    def update_gui(self):
        """Update device list, whitelist, and log viewer."""
        try:
            # Update device list
            current_devices = get_connected_devices()
            if current_devices != self.devices:
                self.devices = current_devices
                self.device_list.delete(0, tk.END)
                for vendor_id, product_id in self.devices:
                    status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                    color = "green" if status == "Authorized" else "red"
                    self.device_list.insert(tk.END, f"{vendor_id}:{product_id} - {status}")
                    self.device_list.itemconfig(tk.END, {'fg': color})

            # Update whitelist list
            self.whitelist_list.delete(0, tk.END)
            try:
                import sqlite3
                conn = sqlite3.connect("devices.db")
                c = conn.cursor()
                c.execute("SELECT vendor_id, product_id FROM whitelist")
                for vendor_id, product_id in c.fetchall():
                    self.whitelist_list.insert(tk.END, f"{vendor_id}:{product_id}")
                conn.close()
            except Exception as e:
                logging.error(f"Error reading whitelist: {e}")
                self.status_var.set(f"Error reading whitelist: {e}")

            # Update log viewer (last 10 events)
            self.log_text.configure(state='normal')
            self.log_text.delete(1.0, tk.END)
            try:
                with open("logs/events.log", "r") as f:
                    lines = f.readlines()[-10:]  # Last 10 lines
                    for line in lines:
                        self.log_text.insert(tk.END, line)
            except Exception as e:
                self.log_text.insert(tk.END, f"Error reading logs: {e}\n")
            self.log_text.configure(state='disabled')

        except Exception as e:
            logging.error(f"GUI update error: {e}")
            self.status_var.set(f"Error: {e}")

        self.root.after(2000, self.update_gui)  # Update every 2 seconds

    def add_to_whitelist(self):
        """Add selected device to whitelist."""
        try:
            if not self.device_list.curselection():
                messagebox.showwarning("Warning", "Please select a device to whitelist.")
                return
            selected = self.device_list.get(tk.ACTIVE)
            vendor_id, product_id = selected.split(" - ")[0].split(":")
            add_to_whitelist(vendor_id, product_id)
            logging.info(f"GUI: Added to whitelist: {vendor_id}:{product_id}")
            self.status_var.set(f"Added {vendor_id}:{product_id} to whitelist")
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added to whitelist.")
            self.update_gui()  # Refresh to reflect new status
        except Exception as e:
            logging.error(f"Error adding to whitelist: {e}")
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to add device: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = USBMonitorGUI(root)
    root.mainloop()