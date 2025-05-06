import tkinter as tk
from logger import setup_logger
from database import create_db
from gui import USBMonitorGUI

if __name__ == "__main__":
    try:
        setup_logger()
        create_db()
        root = tk.Tk()
        app = USBMonitorGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        raise