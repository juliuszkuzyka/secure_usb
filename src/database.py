import sqlite3
import logging
import os
from config import DB_FILE

log = logging.getLogger('secure_usb.database')

def create_db():
    """Create the SQLite database and initialize tables."""
    conn = None
    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                UNIQUE(vendor_id, product_id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                vendor_id TEXT,
                product_id TEXT,
                action TEXT NOT NULL
            )
        ''')
        conn.commit()
        log.info("Database initialized successfully")
    except sqlite3.Error as e:
        log.error(f"Database creation error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def is_device_whitelisted(vendor_id, product_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT 1 FROM whitelist WHERE vendor_id=? AND product_id=?", (vendor_id, product_id))
        return c.fetchone() is not None
    except sqlite3.Error as e:
        log.error(f"Error checking whitelist: {e}")
        return False
    finally:
        if conn:
            conn.close()

def add_to_whitelist(vendor_id, product_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO whitelist (vendor_id, product_id) VALUES (?, ?)", (vendor_id, product_id))
        conn.commit()
        log.info(f"Added to whitelist: {vendor_id}:{product_id}")
    except sqlite3.IntegrityError:
        log.info(f"Device already in whitelist: {vendor_id}:{product_id}")
    except sqlite3.Error as e:
        log.error(f"Error adding to whitelist: {e}")
    finally:
        if conn:
            conn.close()

def remove_from_whitelist(vendor_id, product_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM whitelist WHERE vendor_id=? AND product_id=?", (vendor_id, product_id))
        conn.commit()
        if c.rowcount > 0:
            log.info(f"Removed from whitelist: {vendor_id}:{product_id}")
        else:
            log.warning(f"Device not found in whitelist: {vendor_id}:{product_id}")
    except sqlite3.Error as e:
        log.error(f"Error removing from whitelist: {e}")
    finally:
        if conn:
            conn.close()

def log_event(timestamp, vendor_id, product_id, action):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp, vendor_id, product_id, action) VALUES (?, ?, ?, ?)",
                  (timestamp, vendor_id, product_id, action))
        conn.commit()
        log.debug(f"Logged event: {action} for {vendor_id}:{product_id}")
    except sqlite3.Error as e:
        log.error(f"Error logging event: {e}")
    finally:
        if conn:
            conn.close()

def get_recent_logs(limit=20):
    """Fetch recent USB log events from the database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT timestamp, vendor_id, product_id, action FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        return c.fetchall()
    except sqlite3.Error as e:
        log.error(f"Error fetching recent logs: {e}")
        return []
    finally:
        if conn:
            conn.close()