import sqlite3
import os
import sys

# Ensure parent directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DATABASE_PATH


def _ensure_column(cursor, table: str, column: str, definition: str):
    """Add a column safely if migrating an older single-tenant database."""
    cols = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def setup_database():
    """Initializes the multi-tenant SQLite database with the required schema."""
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 0. sites (Multi-tenant customer websites protected by MIRAGE Shield)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sites (
        site_id             TEXT PRIMARY KEY,
        domain              TEXT NOT NULL UNIQUE,
        target_url          TEXT NOT NULL,
        owner_name          TEXT DEFAULT 'Customer',
        api_key             TEXT NOT NULL UNIQUE,
        dashboard_key       TEXT NOT NULL UNIQUE,
        created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_attack_at      DATETIME,
        total_absorbed      INTEGER DEFAULT 0,
        fake_records_served INTEGER DEFAULT 0
    );
    ''')

    # 1. events
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id     TEXT DEFAULT 'global',
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address  TEXT NOT NULL,
        port        INTEGER,
        protocol    TEXT CHECK(protocol IN ('SSH', 'HTTP', 'FTP', 'HONEYTOKEN', 'SHIELD', 'API')),
        event_type  TEXT NOT NULL,
        details     TEXT,
        threat_pts  INTEGER DEFAULT 0,
        mitre_id    TEXT
    );
    ''')

    # 2. attackers (Global attacker index, kept compatible with core honeypots)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attackers (
        ip_address     TEXT PRIMARY KEY,
        first_seen     DATETIME,
        last_seen      DATETIME,
        total_events   INTEGER DEFAULT 0,
        threat_score   INTEGER DEFAULT 0,
        classification TEXT CHECK(classification IN ('SCANNER', 'SUSPICIOUS', 'ACTIVE_THREAT', 'CRITICAL')),
        country        TEXT,
        city           TEXT,
        isp            TEXT,
        latitude       REAL,
        longitude      REAL,
        is_quarantined BOOLEAN DEFAULT 0
    );
    ''')

    # 2b. site_attackers (Per-website isolated attacker risk profiles)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS site_attackers (
        site_id        TEXT NOT NULL,
        ip_address     TEXT NOT NULL,
        first_seen     DATETIME,
        last_seen      DATETIME,
        total_events   INTEGER DEFAULT 0,
        threat_score   INTEGER DEFAULT 0,
        classification TEXT CHECK(classification IN ('SCANNER', 'SUSPICIOUS', 'ACTIVE_THREAT', 'CRITICAL')),
        country        TEXT,
        city           TEXT,
        isp            TEXT,
        latitude       REAL,
        longitude      REAL,
        is_quarantined BOOLEAN DEFAULT 0,
        PRIMARY KEY (site_id, ip_address)
    );
    ''')

    # 3. credentials
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS credentials (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id     TEXT DEFAULT 'global',
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
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id      TEXT DEFAULT 'global',
        ip_address   TEXT NOT NULL,
        blocked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at   DATETIME,
        reason       TEXT,
        threat_score INTEGER,
        is_active    BOOLEAN DEFAULT 1,
        unblocked_by TEXT
    );
    ''')

    # 5. honeytoken_triggers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS honeytoken_triggers (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id      TEXT DEFAULT 'global',
        timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
        token_name   TEXT NOT NULL,
        token_type   TEXT,
        ip_address   TEXT,
        process_name TEXT,
        details      TEXT
    );
    ''')

    # Safe migrations for pre-existing databases
    for tbl in ('events', 'credentials', 'quarantine_log', 'honeytoken_triggers'):
        _ensure_column(cursor, tbl, 'site_id', "TEXT DEFAULT 'global'")

    # 6. indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_site ON events(site_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_active ON quarantine_log(is_active)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_site ON quarantine_log(site_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_creds_site ON credentials(site_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ht_site ON honeytoken_triggers(site_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sites_apikey ON sites(api_key)')

    conn.commit()
    conn.close()
    print("Database setup complete.")


# Alias for convenience
init_db = setup_database

if __name__ == "__main__":
    setup_database()
