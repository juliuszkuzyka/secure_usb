import customtkinter as ctk
import logging
import os
import sqlite3
from threading import Thread
from tkinter import messagebox

from .usb_monitor import get_connected_devices, monitor_usb
from .database import is_device_whitelisted, add_to_whitelist
from config import LOG_FILE, DB_FILE

class USBMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("USB Security Monitor")
        self.geometry("1000x700")
        self.configure(bg="#1E1E1E")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.devices = set()  # Przechowywanie aktualnej listy urządzeń
        self.setup_ui()
        Thread(target=monitor_usb, daemon=True).start()
        self.update_gui()

    def setup_ui(self):
        self.header_label = ctk.CTkLabel(self, text="USB Security Monitor", font=("Segoe UI", 20, "bold"))
        self.header_label.pack(pady=20)

        self.device_frame = ctk.CTkFrame(self)
        self.device_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.device_label = ctk.CTkLabel(self.device_frame, text="Connected USB Devices", font=("Segoe UI", 14, "bold"))
        self.device_label.pack(pady=5)

        self.device_listbox = ctk.CTkTextbox(self.device_frame, height=150, width=700, font=("Segoe UI", 12), corner_radius=10)
        self.device_listbox.pack(pady=5)

        self.whitelist_frame = ctk.CTkFrame(self)
        self.whitelist_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.whitelist_label = ctk.CTkLabel(self.whitelist_frame, text="Whitelisted Devices", font=("Segoe UI", 14, "bold"))
        self.whitelist_label.pack(pady=5)

        self.whitelist_listbox = ctk.CTkTextbox(self.whitelist_frame, height=100, width=700, font=("Segoe UI", 12), corner_radius=10)
        self.whitelist_listbox.pack(pady=5)

        self.buttons_frame = ctk.CTkFrame(self)
        self.buttons_frame.pack(pady=10)

        self.add_button = ctk.CTkButton(self.buttons_frame, text="Add to Whitelist", command=self.add_to_whitelist, fg_color="#4A90E2")
        self.add_button.pack(side="left", padx=5)

        self.refresh_button = ctk.CTkButton(self.buttons_frame, text="Refresh", command=self.update_gui, fg_color="#357ABD")
        self.refresh_button.pack(side="left", padx=5)

        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_label = ctk.CTkLabel(self.log_frame, text="Recent Events", font=("Segoe UI", 14, "bold"))
        self.log_label.pack(pady=5)

        self.log_text = ctk.CTkTextbox(self.log_frame, height=150, width=700, font=("Consolas", 12), corner_radius=10)
        self.log_text.pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="Monitoring USB devices...", font=("Segoe UI", 12))
        self.status_label.pack(side="bottom", pady=5)

    def update_gui(self):
        try:
            current_devices = get_connected_devices()
            existing_entries = set(self.device_listbox.get("0.0", "end").split("\n"))

            # Aktualizacja listy urządzeń, ale BEZ jej całkowitego czyszczenia
            for vendor_id, product_id in sorted(current_devices):
                status = "Authorized" if is_device_whitelisted(vendor_id, product_id) else "Unauthorized"
                entry = f"{vendor_id}:{product_id} - {status}"

                if entry not in existing_entries:  # Zapobieganie duplikatom
                    self.device_listbox.insert("end", entry + "\n")

            # Pobieranie whitelisty i jej aktualizacja
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT vendor_id, product_id FROM whitelist")
            self.whitelist_listbox.delete("0.0", "end")
            for vid, pid in c.fetchall():
                self.whitelist_listbox.insert("end", f"{vid}:{pid}\n")
            conn.close()

            # Aktualizacja logów
            self.log_text.delete("0.0", "end")
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    self.log_text.insert("end", f.read())
                self.log_text.see("end")

        except Exception as e:
            logging.error(f"GUI update error: {e}")
            self.status_label.configure(text=f"Error: {e}")

        # Dłuższy czas odświeżania GUI (możesz dostosować do potrzeb)
        self.after(5000, self.update_gui)

    def add_to_whitelist(self):
        try:
            selected_text = self.device_listbox.get("0.0", "end").strip()
            if not selected_text:
                messagebox.showwarning("Warning", "Please select a device to whitelist.")
                return

            vendor_id, product_id = selected_text.split(" - ")[0].split(":")
            add_to_whitelist(vendor_id, product_id)
            messagebox.showinfo("Success", f"Device {vendor_id}:{product_id} added.")
            self.update_gui()
        except Exception as e:
            logging.error(f"Add to whitelist error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = USBMonitorApp()
    app.mainloop()
