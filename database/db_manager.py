import sqlite3
import json
from config.settings import DATABASE_PATH
from engine.geo_enricher import GeoEnricher

class DatabaseManager:
    """CRUD operations for MIRAGE Junior database."""

    def __init__(self):
        self.db_path = DATABASE_PATH

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def log_event(self, ip_address, port, protocol, event_type, details=None, threat_pts=0, mitre_id=None):
        conn = self.get_connection()
        c = conn.cursor()
        details_json = json.dumps(details) if details else None
        c.execute('''
            INSERT INTO events (ip_address, port, protocol, event_type, details, threat_pts, mitre_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, port, protocol, event_type, details_json, threat_pts, mitre_id))
        
        # Check if new attacker and enrich with geo data
        c.execute("SELECT ip_address FROM attackers WHERE ip_address = ?", (ip_address,))
        row = c.fetchone()
        if not row:
            geo = None
            try:
                geo = GeoEnricher.lookup(ip_address)
            except Exception:
                pass
            country = geo.get('country') if geo else None
            city = geo.get('city') if geo else None
            isp = geo.get('isp') if geo else None
            lat = geo.get('lat') if geo else None
            lon = geo.get('lon') if geo else None

            c.execute('''
                INSERT INTO attackers (ip_address, first_seen, last_seen, total_events, country, city, isp, latitude, longitude)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET 
                last_seen=CURRENT_TIMESTAMP, total_events=total_events+1
            ''', (ip_address, country, city, isp, lat, lon))
        else:
            c.execute('''
                UPDATE attackers SET 
                last_seen=CURRENT_TIMESTAMP, total_events=total_events+1
                WHERE ip_address=?
            ''', (ip_address,))
        
        conn.commit()
        conn.close()

    def log_credential(self, ip_address, protocol, username, password, success=False):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO credentials (ip_address, protocol, username, password, success)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address, protocol, username, password, success))
        conn.commit()
        conn.close()

    def get_events_by_ip(self, ip_address):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM events WHERE ip_address = ? ORDER BY timestamp ASC", (ip_address,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_all_attackers(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM attackers ORDER BY last_seen DESC")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_threat_score(self, ip_address, score, classification):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            UPDATE attackers SET threat_score=?, classification=? WHERE ip_address=?
        ''', (score, classification, ip_address))
        conn.commit()
        conn.close()

    def get_attacker_profile(self, ip_address):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM attackers WHERE ip_address = ?", (ip_address,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def quarantine_ip(self, ip_address, reason, threat_score, expires_at):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO quarantine_log (ip_address, expires_at, reason, threat_score)
            VALUES (?, ?, ?, ?)
        ''', (ip_address, expires_at, reason, threat_score))
        c.execute("UPDATE attackers SET is_quarantined=1 WHERE ip_address=?", (ip_address,))
        conn.commit()
        conn.close()

    def unquarantine_ip(self, ip_address, unblocked_by='manual'):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            UPDATE quarantine_log SET is_active=0, unblocked_by=? WHERE ip_address=? AND is_active=1
        ''', (unblocked_by, ip_address))
        c.execute("UPDATE attackers SET is_quarantined=0 WHERE ip_address=?", (ip_address,))
        conn.commit()
        conn.close()

    def get_quarantine_log(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM quarantine_log ORDER BY blocked_at DESC")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def log_honeytoken_trigger(self, token_name, token_type, ip_address=None, process_name=None, details=None):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO honeytoken_triggers (token_name, token_type, ip_address, process_name, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (token_name, token_type, ip_address, process_name, details))
        conn.commit()
        conn.close()

    def get_stats(self):
        # Placeholder for dashboard stats
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM events")
        total_hits = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM attackers")
        unique_ips = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM credentials")
        creds = c.fetchone()[0]
        c.execute("SELECT AVG(threat_score) FROM attackers WHERE threat_score > 0")
        avg_score = c.fetchone()[0] or 0
        conn.close()
        return {"total_hits": total_hits, "unique_ips": unique_ips, "credentials_captured": creds, "avg_threat_score": int(avg_score)}

    def get_recent_events(self, limit=50):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_top_attackers(self, limit=10):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM attackers ORDER BY threat_score DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_attack_timeline_data(self):
        # Fetch timeline data logic
        return self.get_recent_events()

    def get_events_for_timeline(self, ip_address):
        return self.get_events_by_ip(ip_address)
