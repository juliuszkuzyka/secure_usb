from src.logger import setup_logger
from src.database import create_db
from src.gui import USBMonitorApp
import tkinter as tk

if __name__ == "__main__":
    setup_logger()
    create_db()
    root = tk.Tk()
    app = USBMonitorApp()
    root.mainloop()
