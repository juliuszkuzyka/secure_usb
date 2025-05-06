# database.py

import sqlite3
from config import DB_FILE

def create_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT,
            product_id TEXT,
            device_name TEXT,
            authorized INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def add_device(vendor_id, product_id, device_name, authorized):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO devices (vendor_id, product_id, device_name, authorized)
        VALUES (?, ?, ?, ?)
    ''', (vendor_id, product_id, device_name, authorized))
    conn.commit()
    conn.close()
