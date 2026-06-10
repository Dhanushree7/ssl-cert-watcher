# ExpirySense SQLite Telemetry Database Configuration
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "expiry_sense.db")

def get_db_connection():
    """Establish connection with sqlite3 file database with row dict factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes sqlite schema and creates the ssl_certificates table if it doesn't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ssl_certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE NOT NULL,
        issuer TEXT,
        expiry_date TEXT,
        days_remaining INTEGER,
        tls_version TEXT,
        status TEXT NOT NULL,
        failure_reason TEXT,
        last_scan TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

def save_certificate_record(record: dict):
    """Saves or updates secure certificate details inside sqlite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now_str = datetime.utcnow().isoformat() + "Z"
    
    cursor.execute("""
    INSERT INTO ssl_certificates (
        hostname, issuer, expiry_date, days_remaining, tls_version, status, failure_reason, last_scan
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(hostname) DO UPDATE SET
        issuer=excluded.issuer,
        expiry_date=excluded.expiry_date,
        days_remaining=excluded.days_remaining,
        tls_version=excluded.tls_version,
        status=excluded.status,
        failure_reason=excluded.failure_reason,
        last_scan=excluded.last_scan;
    """, (
        record["hostname"],
        record.get("issuer"),
        record.get("expiry_date"),
        record.get("days_remaining"),
        record.get("tls_version"),
        record["status"],
        record.get("failure_reason"),
        now_str
    ))
    conn.commit()
    conn.close()

def get_all_certificates():
    """Retrieves all certificate telemetry records sorted by risk levels then days remaining."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM ssl_certificates 
        ORDER BY 
            CASE status
                WHEN 'CRITICAL' THEN 1
                WHEN 'WARNING' THEN 2
                WHEN 'HEALTHY' THEN 3
                ELSE 4
            END ASC,
            days_remaining ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def delete_certificate_record(cert_id: int):
    """Deletes a single host connection record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ssl_certificates WHERE id = ?", (cert_id,))
    conn.commit()
    affected_rows = cursor.rowcount
    conn.close()
    return affected_rows > 0
