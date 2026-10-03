import sqlite3
import os
import sys

# Ensure parent directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DATABASE_PATH

def setup_database():
    """Initializes the SQLite database with the required schema."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 1. events
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address  TEXT NOT NULL,
        port        INTEGER,
        protocol    TEXT CHECK(protocol IN ('SSH', 'HTTP', 'FTP', 'HONEYTOKEN')),
        event_type  TEXT NOT NULL,
        details     TEXT,
        threat_pts  INTEGER DEFAULT 0,
        mitre_id    TEXT
    );
    ''')

    # 2. attackers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attackers (
        ip_address    TEXT PRIMARY KEY,
        first_seen    DATETIME,
        last_seen     DATETIME,
        total_events  INTEGER DEFAULT 0,
        threat_score  INTEGER DEFAULT 0,
        classification TEXT CHECK(classification IN ('SCANNER', 'SUSPICIOUS', 'ACTIVE_THREAT', 'CRITICAL')),
        country       TEXT,
        city          TEXT,
        isp           TEXT,
        latitude      REAL,
        longitude     REAL,
        is_quarantined BOOLEAN DEFAULT 0
    );
    ''')

    # 3. credentials
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS credentials (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address  TEXT NOT NULL,
        protocol    TEXT,
        username    TEXT,
        password    TEXT,
        success     BOOLEAN DEFAULT 0
    );
    ''')

    # 4. quarantine_log
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS quarantine_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address  TEXT NOT NULL,
        blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at  DATETIME,
        reason      TEXT,
        threat_score INTEGER,
        is_active   BOOLEAN DEFAULT 1,
        unblocked_by TEXT
    );
    ''')

    # 5. honeytoken_triggers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS honeytoken_triggers (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        token_name  TEXT NOT NULL,
        token_type  TEXT,
        ip_address  TEXT,
        process_name TEXT,
        details     TEXT
    );
    ''')

    conn.commit()
    conn.close()
    print("Database setup complete.")

# Alias for convenience
init_db = setup_database

if __name__ == "__main__":
    setup_database()
