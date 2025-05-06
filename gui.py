import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
import logging
from usb_monitor import get_connected_devices, monitor_usb
from database import add_to_whitelist, is_device_whitelisted

class USBMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Security Monitor")
        self.root.geometry("900x600")
        self.root.configure(bg="#2E2E2E")
        self.devices = set()
        logging.debug("Initializing GUI...")

        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", foreground="white", background="#2E2E2E", font=("Helvetica", 12))
        style.configure("TListbox", background="#3C3F41", foreground="white", font=("Helvetica", 10))
        style.configure("TButton", background="#4A90E2", foreground="white", font=("Helvetica", 10))

        # Device List Frame
        self.device_frame = ttk.LabelFrame(root, text="Connected USB Devices", style="TLabel")
        self.device_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.device_list = tk.Listbox(self.device_frame, width=60, height=10, bg="#3C3F41", fg="white", font=("Helvetica", 10))
        self.device_list.pack(padx=5, pady=5)
        self.device_list.bind('<<ListboxSelect>>', self.on_device_select)

        # Device Buttons
        self.device_buttons = ttk.Frame(self.device_frame)
        self.device_buttons.pack(pady=5)
        ttk.Button(self.device_buttons, text="Add to Whitelist", command=self.add_to_whitelist, style="TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(self.device_buttons, text="Refresh", command=self.update_gui, style="TButton").pack(side=tk.LEFT, padx=5)

        # Whitelist Frame
        self.whitelist_frame = ttk.LabelFrame(root, text="Whitelisted Devices", style="TLabel")
        self.whitelist_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.whitelist_list = tk.Listbox(self.whitelist_frame, width=60, height=5, bg="#3C3F41", fg="white", font=("Helvetica", 10))
        self.whitelist_list.pack(padx=5, pady=5)

        # Log Frame
        self.log_frame = ttk.LabelFrame(root, text="Recent Events", style="TLabel")
        self.log_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.log_text = tk.Text(self.log_frame, width=60, height=5, bg="#3C3F41", fg="white", font=("Helvetica", 10), state='disabled')
        self.log_text.pack(padx=5, pady=5)

        # Status Bar
        self.status_var = tk.StringVar(value="Monitoring USB devices...")
        self.status_label = ttk.Label(root, textvariable=self.status_var, style="TLabel", anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

        # Start monitoring
        self.monitor_thread = Thread(target=monitor_usb, daemon=True)
        self.monitor_thread.start()
        logging.debug("Monitoring thread started.")

        # Initial update
        self.update_gui()

    def on_device_select(self, event):
        try:
            selected = self.device_list.get(tk.ACTIVE)
            if selected:
                self.status_var.set(f"Selected: {selected}")
        except Exception as e:
            logging.error(f"Error in on_device_select: {e}")

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            if current_devices != self.devices:
                self.devices = current_devices
                self.device_list.delete(0, tk.END)
                for vendor_id, product_id in self.devices:
                    status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                    color = "green" if status == "Authorized" else "red"
                    self.device_list.insert(tk.END, f"{vendor_id}:{product_id} - {status}")
                    self.device_list.itemconfig(tk.END, {'fg': color})

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

            self.log_text.configure(state='normal')
            self.log_text.delete(1.0, tk.END)
            try:
                with open("logs/events.log", "r") as f:
                    lines = f.readlines()[-10:]
                    for line in lines:
                        self.log_text.insert(tk.END, line)
            except Exception as e:
                self.log_text.insert(tk.END, f"Error reading logs: {e}\n")
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
            logging.info(f"GUI: Added to whitelist: {vendor_id}:{product_id}")
            self.status_var.set(f"Added {vendor_id}:{product_id} to whitelist")
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added to whitelist.")
            self.update_gui()
        except Exception as e:
            logging.error(f"Error adding to whitelist: {e}")
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to add device: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = USBMonitorGUI(root)
    root.mainloop()