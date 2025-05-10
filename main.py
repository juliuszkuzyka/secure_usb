from src.logger import setup_logger
from src.database import create_db
from src.gui import USBMonitorApp

if __name__ == "__main__":
    setup_logger()
    create_db()
    app = USBMonitorApp()
    app.mainloop()