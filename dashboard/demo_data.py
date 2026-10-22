"""
MIRAGE Junior — Demo & Vercel Data Seeder
Seeds the database with 15 fresh realistic multi-protocol attack scenarios.
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta

def seed_data():
    import config.settings as settings_cfg
    from database.db_setup import init_db

    db_path = getattr(settings_cfg, 'DATABASE_PATH', os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'database', 'mirage_junior.db'))

    if os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    init_db()

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    c = conn.cursor()

    # Clear old data
    c.execute("DELETE FROM events")
    c.execute("DELETE FROM attackers")
    c.execute("DELETE FROM credentials")
    c.execute("DELETE FROM quarantine_log")
    c.execute("DELETE FROM honeytoken_triggers")

    now = datetime.now()

    # 15 Realistic Attackers
    attackers = [
        ('185.220.101.45', 'Germany', 'Frankfurt', 'Tor Exit Node', 50.1109, 8.6821, 92, 'CRITICAL', 1),
        ('194.26.29.112', 'Russia', 'Moscow', 'Selectel Network', 55.7558, 37.6173, 86, 'CRITICAL', 1),
        ('45.155.205.233', 'Netherlands', 'Amsterdam', 'DigitalOcean LLC', 52.3676, 4.9041, 88, 'CRITICAL', 1),
        ('103.203.57.18', 'India', 'Mumbai', 'Airtel Broadband', 19.0760, 72.8777, 45, 'SUSPICIOUS', 0),
        ('209.97.177.91', 'USA', 'Atlanta', 'DigitalOcean Cloud', 33.7490, -84.3880, 85, 'CRITICAL', 1),
        ('103.22.4.88', 'China', 'Beijing', 'China Telecom Backbone', 39.9042, 116.4074, 78, 'CRITICAL', 1),
        ('200.174.198.42', 'Brazil', 'Sao Paulo', 'Telefonica Brasil', -23.5505, -46.6333, 62, 'ACTIVE_THREAT', 0),
        ('178.128.87.15', 'Singapore', 'Singapore', 'DigitalOcean Singapore', 1.3521, 103.8198, 58, 'ACTIVE_THREAT', 0),
        ('46.101.245.17', 'United Kingdom', 'London', 'Linode Cloud', 51.5074, -0.1278, 68, 'ACTIVE_THREAT', 0),
        ('106.51.82.173', 'India', 'Bangalore', 'ACT Fibernet', 12.9716, 77.5946, 18, 'SCANNER', 0),
        ('41.231.53.9', 'Tunisia', 'Tunis', 'Tunisie Telecom', 36.8065, 10.1815, 12, 'SCANNER', 0),
        ('68.183.55.22', 'USA', 'Dallas', 'DigitalOcean Cloud', 32.7767, -96.7970, 32, 'SUSPICIOUS', 0),
        ('51.15.23.190', 'France', 'Paris', 'Scaleway Datacenter', 48.8566, 2.3522, 90, 'CRITICAL', 1),
        ('211.234.110.82', 'South Korea', 'Seoul', 'Korea Telecom', 37.5665, 126.9780, 55, 'ACTIVE_THREAT', 0),
        ('198.51.100.77', 'Canada', 'Toronto', 'Rogers Cable', 43.6532, -79.3832, 10, 'SCANNER', 0),
    ]

    for atk in attackers:
        first_seen = (now - timedelta(hours=3, minutes=20)).strftime('%Y-%m-%d %H:%M:%S')
        last_seen = (now - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO attackers (ip_address, first_seen, last_seen, total_events, threat_score, classification,
                                   country, city, isp, latitude, longitude, is_quarantined)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (atk[0], first_seen, last_seen, 4, atk[6], atk[7], atk[1], atk[2], atk[3], atk[4], atk[5], atk[8]))

    # Events Data
    events_data = [
        ('185.220.101.45', now - timedelta(hours=2, minutes=45), 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
        ('185.220.101.45', now - timedelta(hours=2, minutes=40), 8080, 'HTTP', 'targeted_recon', '{"path": "/.env"}', 25, 'T1552.001'),
        ('185.220.101.45', now - timedelta(hours=2, minutes=35), 8080, 'HTTP', 'sql_injection', '{"path": "/phpmyadmin/", "payload": "admin\' OR \'1\'=\'1\'--"}', 20, 'T1190'),
        ('185.220.101.45', now - timedelta(hours=2, minutes=30), 8080, 'HTTP', 'login_attempt', '{"path": "/admin", "user": "admin"}', 8, 'T1110'),
        ('194.26.29.112', now - timedelta(hours=2, minutes=15), 2222, 'SSH', 'connection', '{"banner": "OpenSSH_7.6p1"}', 5, 'T1046'),
        ('194.26.29.112', now - timedelta(hours=2, minutes=10), 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "admin1234"}', 8, 'T1110'),
        ('194.26.29.112', now - timedelta(hours=2, minutes=5), 2222, 'SSH', 'shell_command', '{"command": "whoami", "output": "root"}', 15, 'T1033'),
        ('194.26.29.112', now - timedelta(hours=2, minutes=4), 2222, 'SSH', 'shell_command', '{"command": "cat /etc/passwd"}', 10, 'T1087.001'),
        ('45.155.205.233', now - timedelta(hours=1, minutes=50), 8080, 'HTTP', 'scan', '{"path": "/api/config"}', 20, 'T1552.001'),
        ('45.155.205.233', now - timedelta(hours=1, minutes=45), 8080, 'HONEYTOKEN', 'honeytoken_access', '{"file": ".env", "accessed_key": "AWS_KEY"}', 40, 'T1552.001'),
        ('103.203.57.18', now - timedelta(hours=1, minutes=30), 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
        ('103.203.57.18', now - timedelta(hours=1, minutes=25), 8080, 'HTTP', 'directory_traversal', '{"path": "../../../../etc/passwd"}', 20, 'T1083'),
        ('209.97.177.91', now - timedelta(hours=1, minutes=10), 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
        ('209.97.177.91', now - timedelta(hours=1, minutes=2), 2121, 'HONEYTOKEN', 'honeytoken_access', '{"file": "credentials.xlsx"}', 40, 'T1005'),
        ('103.22.4.88', now - timedelta(minutes=55), 2222, 'SSH', 'login_attempt', '{"username": "admin", "password": "admin"}', 8, 'T1078.001'),
        ('103.22.4.88', now - timedelta(minutes=50), 2222, 'SSH', 'shell_command', '{"command": "uname -a"}', 15, 'T1082'),
        ('200.174.198.42', now - timedelta(minutes=45), 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
        ('200.174.198.42', now - timedelta(minutes=42), 2121, 'FTP', 'file_access', '{"file": "backup_database.sql"}', 20, 'T1005'),
        ('178.128.87.15', now - timedelta(minutes=38), 2222, 'SSH', 'login_attempt', '{"username": "ubuntu", "password": "ubuntu123"}', 8, 'T1110'),
        ('46.101.245.17', now - timedelta(minutes=30), 8080, 'HTTP', 'scan', '{"path": "/wp-login.php"}', 5, 'T1046'),
        ('46.101.245.17', now - timedelta(minutes=28), 8080, 'HTTP', 'login_attempt', '{"path": "/wp-login.php", "user": "admin"}', 8, 'T1110'),
        ('106.51.82.173', now - timedelta(minutes=22), 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
        ('41.231.53.9', now - timedelta(minutes=18), 8080, 'HTTP', 'scan', '{"path": "/phpmyadmin/"}', 5, 'T1046'),
        ('68.183.55.22', now - timedelta(minutes=15), 8080, 'HTTP', 'scan', '{"path": "/admin"}', 5, 'T1046'),
        ('51.15.23.190', now - timedelta(minutes=10), 8080, 'HONEYTOKEN', 'honeytoken_access', '{"file": ".env"}', 40, 'T1552.001'),
        ('211.234.110.82', now - timedelta(minutes=6), 2222, 'SSH', 'login_attempt', '{"username": "oracle", "password": "oracle"}', 8, 'T1110'),
        ('198.51.100.77', now - timedelta(minutes=2), 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
    ]

    for ip, dt, port, proto, ev_type, details, pts, mitre in events_data:
        ts_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO events (timestamp, ip_address, port, protocol, event_type, details, threat_pts, mitre_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts_str, ip, port, proto, ev_type, details, pts, mitre))

    # Credentials Data
    credentials_data = [
        ('185.220.101.45', 'HTTP', 'admin', 'password123'),
        ('194.26.29.112', 'SSH', 'root', 'admin1234'),
        ('194.26.29.112', 'SSH', 'root', 'toor'),
        ('45.155.205.233', 'HTTP', 'wp_admin', 'letmein123'),
        ('103.203.57.18', 'HTTP', 'admin', '12345678'),
        ('103.22.4.88', 'SSH', 'admin', 'admin'),
        ('103.22.4.88', 'SSH', 'root', 'password'),
        ('178.128.87.15', 'SSH', 'ubuntu', 'ubuntu123'),
        ('46.101.245.17', 'HTTP', 'admin', 'password2026'),
        ('68.183.55.22', 'HTTP', 'support', 'welcome'),
        ('211.234.110.82', 'SSH', 'oracle', 'oracle'),
        ('200.174.198.42', 'FTP', 'anonymous', 'guest@ftp'),
        ('209.97.177.91', 'FTP', 'anonymous', 'test@corp'),
    ]

    for ip, proto, user, pwd in credentials_data:
        c.execute("""
            INSERT INTO credentials (timestamp, ip_address, protocol, username, password, success)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (now.strftime('%Y-%m-%d %H:%M:%S'), ip, proto, user, pwd))

    # Quarantine Data
    quarantine_data = [
        ('185.220.101.45', 92, 'Threat score 92 exceeded critical threshold (25). Planted .env touched.', 1),
        ('194.26.29.112', 86, 'Threat score 86 exceeded critical threshold (25). Interactive SSH shell achieved.', 1),
        ('45.155.205.233', 88, 'Threat score 88 exceeded critical threshold (25). Honeytoken .env exfiltrated.', 1),
        ('209.97.177.91', 85, 'Threat score 85 exceeded critical threshold (25). credentials.xlsx downloaded via FTP.', 1),
        ('103.22.4.88', 78, 'Threat score 78 exceeded threshold (25). Root brute-force dictionary attack.', 1),
        ('51.15.23.190', 90, 'Threat score 90 exceeded threshold (25). Honeytoken tripwire tripped.', 1),
        ('178.128.87.15', 58, 'Threat score 58 exceeded threshold (25)', 0),
    ]

    for ip, score, reason, is_active in quarantine_data:
        blocked_at = (now - timedelta(minutes=25 if is_active else 90)).strftime('%Y-%m-%d %H:%M:%S')
        expires_at = (now + timedelta(minutes=35 if is_active else -30)).strftime('%Y-%m-%d %H:%M:%S')
        unblocked_by = None if is_active else 'auto_expire'
        c.execute("""
            INSERT INTO quarantine_log (ip_address, blocked_at, expires_at, reason, threat_score, is_active, unblocked_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, blocked_at, expires_at, reason, score, is_active, unblocked_by))

    # Honeytoken Triggers
    honeytoken_triggers = [
        ('.env', 'http_endpoint', '185.220.101.45', 'Accessed /.env decoy web endpoint'),
        ('.env', 'http_endpoint', '45.155.205.233', 'Extracted AWS_SECRET_ACCESS_KEY from /.env'),
        ('.env', 'http_endpoint', '51.15.23.190', 'Accessed /.env via automated web probe'),
        ('credentials.xlsx', 'ftp_file', '209.97.177.91', 'Downloaded credentials.xlsx via FTP port 2121'),
        ('backup_database.sql', 'ftp_file', '200.174.198.42', 'Attempted download of backup_database.sql'),
        ('backup_database.sql', 'filesystem', '127.0.0.1', 'Local file access detected by watchdog daemon'),
    ]

    for name, ttype, ip, details in honeytoken_triggers:
        c.execute("""
            INSERT INTO honeytoken_triggers (timestamp, token_name, token_type, ip_address, details)
            VALUES (?, ?, ?, ?, ?)
        """, (now.strftime('%Y-%m-%d %H:%M:%S'), name, ttype, ip, details))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    seed_data()
