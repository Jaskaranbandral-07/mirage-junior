import json
import re
import secrets
import sqlite3
from urllib.parse import urlparse

from config.settings import DATABASE_PATH
from engine.geo_enricher import GeoEnricher


class DatabaseManager:
    """Multi-tenant CRUD operations for MIRAGE Shield database."""

    def __init__(self):
        self.db_path = DATABASE_PATH

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    # ═══════════════════════════════════════════════════
    # Tenant / Protected Website Management
    # ═══════════════════════════════════════════════════

    @staticmethod
    def normalize_site_target(domain_or_url: str) -> tuple:
        """Return (site_id, domain, target_url) normalized for any URL or host."""
        raw = (domain_or_url or "").strip()
        if not raw:
            raise ValueError("Target URL or domain cannot be empty.")
        if not raw.startswith(("http://", "https://")):
            scheme = "http://" if raw.startswith(("127.0.0.1", "localhost")) else "https://"
            raw = scheme + raw
        parsed = urlparse(raw)
        domain = (parsed.netloc or parsed.path.split("/")[0]).strip().lower()
        if not domain:
            raise ValueError("Invalid domain or URL.")
        target_url = f"{parsed.scheme}://{domain}"
        slug = re.sub(r"[^a-z0-9]+", "-", domain).strip("-")[:48] or "site"
        return slug, domain, target_url

    def register_or_get_site(self, domain_or_url: str, owner_name: str = "Customer") -> dict:
        """Create or fetch an isolated customer workspace for a website."""
        site_id, domain, target_url = self.normalize_site_target(domain_or_url)
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        existing = c.execute(
            "SELECT * FROM sites WHERE domain = ? OR site_id = ?",
            (domain, site_id),
        ).fetchone()
        if existing:
            # Update target_url if scheme changed
            if existing["target_url"] != target_url:
                c.execute(
                    "UPDATE sites SET target_url = ? WHERE site_id = ?",
                    (target_url, existing["site_id"]),
                )
                conn.commit()
                existing = c.execute(
                    "SELECT * FROM sites WHERE site_id = ?",
                    (existing["site_id"],),
                ).fetchone()
            res = dict(existing)
            conn.close()
            return res

        api_key = f"ms_live_{secrets.token_hex(16)}"
        dashboard_key = f"dash_{secrets.token_hex(12)}"
        clean_owner = (owner_name or "Customer").strip()[:80] or "Customer"

        c.execute(
            '''
            INSERT INTO sites (site_id, domain, target_url, owner_name, api_key, dashboard_key)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (site_id, domain, target_url, clean_owner, api_key, dashboard_key),
        )
        conn.commit()
        created = c.execute("SELECT * FROM sites WHERE site_id = ?", (site_id,)).fetchone()
        conn.close()
        return dict(created)

    def get_site(self, site_id: str) -> dict | None:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM sites WHERE site_id = ?", (site_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_site_by_domain(self, domain: str) -> dict | None:
        clean = (domain or "").strip().lower()
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM sites WHERE domain = ?", (clean,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_site_by_api_key(self, api_key: str) -> dict | None:
        key = (api_key or "").strip()
        if not key:
            return None
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM sites WHERE api_key = ?", (key,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def list_sites(self) -> list:
        """List all protected customer websites with live per-site counters."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            '''
            SELECT s.*,
                   (SELECT COUNT(*) FROM events e WHERE e.site_id = s.site_id) AS event_count,
                   (SELECT COUNT(*) FROM site_attackers sa WHERE sa.site_id = s.site_id) AS attacker_count,
                   (SELECT COUNT(*) FROM credentials cr WHERE cr.site_id = s.site_id) AS cred_count,
                   (SELECT COUNT(*) FROM quarantine_log q WHERE q.site_id = s.site_id AND q.is_active = 1) AS active_blocks
            FROM sites s
            ORDER BY COALESCE(s.last_attack_at, s.created_at) DESC
            '''
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def increment_site_deception(self, site_id: str, absorbed_delta: int = 0, fake_records_delta: int = 0):
        if not site_id or site_id == "global":
            return
        conn = self.get_connection()
        conn.execute(
            '''
            UPDATE sites
            SET total_absorbed = total_absorbed + ?,
                fake_records_served = fake_records_served + ?,
                last_attack_at = CURRENT_TIMESTAMP
            WHERE site_id = ?
            ''',
            (int(absorbed_delta), int(fake_records_delta), site_id),
        )
        conn.commit()
        conn.close()

    def clear_site_telemetry(self, site_id: str):
        """Purge telemetry strictly for one customer website without touching other sites."""
        conn = self.get_connection()
        for tbl in ("events", "site_attackers", "credentials", "quarantine_log", "honeytoken_triggers"):
            conn.execute(f"DELETE FROM {tbl} WHERE site_id = ?", (site_id,))
        conn.execute(
            "UPDATE sites SET total_absorbed = 0, fake_records_served = 0, last_attack_at = NULL WHERE site_id = ?",
            (site_id,),
        )
        conn.commit()
        conn.close()

    def delete_site(self, site_id: str):
        self.clear_site_telemetry(site_id)
        conn = self.get_connection()
        conn.execute("DELETE FROM sites WHERE site_id = ?", (site_id,))
        conn.commit()
        conn.close()

    # ═══════════════════════════════════════════════════
    # Event, Attacker & Telemetry Logging (Site-Scoped)
    # ═══════════════════════════════════════════════════

    def log_event(self, ip_address, port, protocol, event_type, details=None,
                  threat_pts=0, mitre_id=None, site_id="global"):
        site_id = site_id or "global"
        conn = self.get_connection()
        c = conn.cursor()
        details_json = json.dumps(details) if details else None
        c.execute(
            '''
            INSERT INTO events (site_id, ip_address, port, protocol, event_type, details, threat_pts, mitre_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (site_id, ip_address, port, protocol, event_type, details_json, threat_pts, mitre_id),
        )

        # Look up GeoIP once if IP not yet seen globally
        row = c.execute("SELECT country, city, isp, latitude, longitude FROM attackers WHERE ip_address = ?", (ip_address,)).fetchone()
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

            c.execute(
                '''
                INSERT INTO attackers (ip_address, first_seen, last_seen, total_events, country, city, isp, latitude, longitude)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen=CURRENT_TIMESTAMP, total_events=total_events+1
                ''',
                (ip_address, country, city, isp, lat, lon),
            )
        else:
            country, city, isp, lat, lon = row
            c.execute(
                '''
                UPDATE attackers SET
                    last_seen=CURRENT_TIMESTAMP, total_events=total_events+1
                WHERE ip_address=?
                ''',
                (ip_address,),
            )

        # Maintain isolated per-site attacker profile when scoped to a website
        if site_id != "global":
            c.execute(
                '''
                INSERT INTO site_attackers (site_id, ip_address, first_seen, last_seen, total_events, country, city, isp, latitude, longitude)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(site_id, ip_address) DO UPDATE SET
                    last_seen=CURRENT_TIMESTAMP, total_events=total_events+1
                ''',
                (site_id, ip_address, country, city, isp, lat, lon),
            )
            c.execute(
                "UPDATE sites SET last_attack_at = CURRENT_TIMESTAMP WHERE site_id = ?",
                (site_id,),
            )

        conn.commit()
        conn.close()

    def log_credential(self, ip_address, protocol, username, password, success=False, site_id="global"):
        site_id = site_id or "global"
        conn = self.get_connection()
        conn.execute(
            '''
            INSERT INTO credentials (site_id, ip_address, protocol, username, password, success)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (site_id, ip_address, protocol, username, password, success),
        )
        conn.commit()
        conn.close()

    def get_events_by_ip(self, ip_address, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute(
                "SELECT * FROM events WHERE ip_address = ? AND site_id = ? ORDER BY timestamp ASC",
                (ip_address, site_id),
            )
        else:
            c.execute("SELECT * FROM events WHERE ip_address = ? ORDER BY timestamp ASC", (ip_address,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_all_attackers(self, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute("SELECT * FROM site_attackers WHERE site_id = ? ORDER BY last_seen DESC", (site_id,))
        else:
            c.execute("SELECT * FROM attackers ORDER BY last_seen DESC")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_threat_score(self, ip_address, score, classification, site_id="global"):
        conn = self.get_connection()
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute(
                "UPDATE site_attackers SET threat_score=?, classification=? WHERE site_id=? AND ip_address=?",
                (score, classification, site_id, ip_address),
            )
        # Keep global score synced to the highest observed score for that IP
        row = c.execute("SELECT threat_score FROM attackers WHERE ip_address=?", (ip_address,)).fetchone()
        if row and (row[0] or 0) <= score or not site_id or site_id == "global":
            c.execute(
                "UPDATE attackers SET threat_score=?, classification=? WHERE ip_address=?",
                (score, classification, ip_address),
            )
        conn.commit()
        conn.close()

    def get_attacker_profile(self, ip_address, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            row = c.execute(
                "SELECT * FROM site_attackers WHERE site_id = ? AND ip_address = ?",
                (site_id, ip_address),
            ).fetchone()
        else:
            row = c.execute("SELECT * FROM attackers WHERE ip_address = ?", (ip_address,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def quarantine_ip(self, ip_address, reason, threat_score, expires_at, site_id="global"):
        site_id = site_id or "global"
        conn = self.get_connection()
        c = conn.cursor()
        existing = c.execute(
            "SELECT id FROM quarantine_log WHERE site_id = ? AND ip_address = ? AND is_active = 1",
            (site_id, ip_address),
        ).fetchone()
        if existing:
            c.execute(
                '''
                UPDATE quarantine_log
                SET expires_at = ?, reason = ?, threat_score = ?, blocked_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''',
                (expires_at, reason, threat_score, existing[0]),
            )
        else:
            c.execute(
                '''
                INSERT INTO quarantine_log (site_id, ip_address, expires_at, reason, threat_score)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (site_id, ip_address, expires_at, reason, threat_score),
            )
        if site_id != "global":
            c.execute(
                "UPDATE site_attackers SET is_quarantined=1 WHERE site_id=? AND ip_address=?",
                (site_id, ip_address),
            )
        c.execute("UPDATE attackers SET is_quarantined=1 WHERE ip_address=?", (ip_address,))
        conn.commit()
        conn.close()

    def unquarantine_ip(self, ip_address, unblocked_by='manual', site_id=None):
        conn = self.get_connection()
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute(
                "UPDATE quarantine_log SET is_active=0, unblocked_by=? WHERE site_id=? AND ip_address=? AND is_active=1",
                (unblocked_by, site_id, ip_address),
            )
            c.execute(
                "UPDATE site_attackers SET is_quarantined=0 WHERE site_id=? AND ip_address=?",
                (site_id, ip_address),
            )
        else:
            c.execute(
                "UPDATE quarantine_log SET is_active=0, unblocked_by=? WHERE ip_address=? AND is_active=1",
                (unblocked_by, ip_address),
            )
            c.execute("UPDATE site_attackers SET is_quarantined=0 WHERE ip_address=?", (ip_address,))
            c.execute("UPDATE attackers SET is_quarantined=0 WHERE ip_address=?", (ip_address,))
        conn.commit()
        conn.close()

    def get_quarantine_log(self, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute("SELECT * FROM quarantine_log WHERE site_id = ? ORDER BY blocked_at DESC", (site_id,))
        else:
            c.execute("SELECT * FROM quarantine_log ORDER BY blocked_at DESC")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def log_honeytoken_trigger(self, token_name, token_type, ip_address=None,
                               process_name=None, details=None, site_id="global"):
        site_id = site_id or "global"
        conn = self.get_connection()
        conn.execute(
            '''
            INSERT INTO honeytoken_triggers (site_id, token_name, token_type, ip_address, process_name, details)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (site_id, token_name, token_type, ip_address, process_name, details),
        )
        conn.commit()
        conn.close()

    def get_stats(self, site_id=None):
        conn = self.get_connection()
        c = conn.cursor()
        if site_id and site_id != "global":
            total_hits = c.execute("SELECT COUNT(*) FROM events WHERE site_id = ?", (site_id,)).fetchone()[0]
            unique_ips = c.execute("SELECT COUNT(*) FROM site_attackers WHERE site_id = ?", (site_id,)).fetchone()[0]
            creds = c.execute("SELECT COUNT(*) FROM credentials WHERE site_id = ?", (site_id,)).fetchone()[0]
            avg_score = c.execute("SELECT AVG(threat_score) FROM site_attackers WHERE site_id = ? AND threat_score > 0", (site_id,)).fetchone()[0] or 0
        else:
            total_hits = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            unique_ips = c.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
            creds = c.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            avg_score = c.execute("SELECT AVG(threat_score) FROM attackers WHERE threat_score > 0").fetchone()[0] or 0
        conn.close()
        return {
            "total_hits": total_hits,
            "unique_ips": unique_ips,
            "credentials_captured": creds,
            "avg_threat_score": int(avg_score),
        }

    def get_site_dashboard_data(self, site_id: str) -> dict:
        """Fetch isolated analytics, events, creds, and quarantines for one website."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row

        total_hits = conn.execute("SELECT COUNT(*) FROM events WHERE site_id = ?", (site_id,)).fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(*) FROM site_attackers WHERE site_id = ?", (site_id,)).fetchone()[0]
        creds_captured = conn.execute("SELECT COUNT(*) FROM credentials WHERE site_id = ?", (site_id,)).fetchone()[0]
        avg_score_row = conn.execute(
            "SELECT AVG(threat_score) FROM site_attackers WHERE site_id = ? AND threat_score > 0",
            (site_id,),
        ).fetchone()[0]
        avg_score = int(avg_score_row) if avg_score_row else 0
        quarantined = conn.execute(
            "SELECT COUNT(DISTINCT ip_address) FROM quarantine_log WHERE site_id = ? AND is_active = 1",
            (site_id,),
        ).fetchone()[0]

        dist = {}
        for cls_name in ("SCANNER", "SUSPICIOUS", "ACTIVE_THREAT", "CRITICAL"):
            dist[cls_name] = conn.execute(
                "SELECT COUNT(*) FROM site_attackers WHERE site_id = ? AND classification = ?",
                (site_id, cls_name),
            ).fetchone()[0]

        countries = {
            r["country"]: r["cnt"]
            for r in conn.execute(
                "SELECT country, COUNT(*) as cnt FROM site_attackers WHERE site_id = ? AND country IS NOT NULL AND country != '' GROUP BY country ORDER BY cnt DESC LIMIT 5",
                (site_id,),
            ).fetchall()
        }

        mitre = {
            r["mitre_id"]: r["cnt"]
            for r in conn.execute(
                "SELECT mitre_id, COUNT(*) as cnt FROM events WHERE site_id = ? AND mitre_id IS NOT NULL AND mitre_id != '' GROUP BY mitre_id ORDER BY cnt DESC LIMIT 8",
                (site_id,),
            ).fetchall()
        }

        hourly = [
            {"hour": r["hour"], "count": r["cnt"]}
            for r in conn.execute(
                """SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt
                   FROM events WHERE site_id = ? AND timestamp >= datetime('now', '-24 hours')
                   GROUP BY hour ORDER BY hour""",
                (site_id,),
            ).fetchall()
        ]

        recent_events = [
            dict(r)
            for r in conn.execute(
                """SELECT e.*, sa.country, sa.classification, sa.threat_score
                   FROM events e
                   LEFT JOIN site_attackers sa ON e.site_id = sa.site_id AND e.ip_address = sa.ip_address
                   WHERE e.site_id = ?
                   ORDER BY e.timestamp DESC LIMIT 25""",
                (site_id,),
            ).fetchall()
        ]

        credentials = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM credentials WHERE site_id = ? ORDER BY timestamp DESC LIMIT 20",
                (site_id,),
            ).fetchall()
        ]

        active_quarantines = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM quarantine_log WHERE site_id = ? AND is_active = 1 ORDER BY blocked_at DESC",
                (site_id,),
            ).fetchall()
        ]

        honeytokens = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM honeytoken_triggers WHERE site_id = ? ORDER BY timestamp DESC LIMIT 20",
                (site_id,),
            ).fetchall()
        ]

        conn.close()
        return {
            "total_hits": total_hits,
            "unique_ips": unique_ips,
            "creds_captured": creds_captured,
            "avg_threat_score": avg_score,
            "ips_quarantined": quarantined,
            "threat_distribution": {
                "Scanner": dist["SCANNER"],
                "Suspicious": dist["SUSPICIOUS"],
                "Active": dist["ACTIVE_THREAT"],
                "Critical": dist["CRITICAL"],
            },
            "top_countries": countries,
            "mitre_stats": mitre,
            "hourly_timeline": hourly,
            "recent_events": recent_events,
            "credentials": credentials,
            "active_quarantines": active_quarantines,
            "honeytokens": honeytokens,
        }

    def get_recent_events(self, limit=50, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute("SELECT * FROM events WHERE site_id = ? ORDER BY timestamp DESC LIMIT ?", (site_id, limit))
        else:
            c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_top_attackers(self, limit=10, site_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if site_id and site_id != "global":
            c.execute("SELECT * FROM site_attackers WHERE site_id = ? ORDER BY threat_score DESC LIMIT ?", (site_id, limit))
        else:
            c.execute("SELECT * FROM attackers ORDER BY threat_score DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_attack_timeline_data(self):
        return self.get_recent_events()
