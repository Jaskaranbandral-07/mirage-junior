"""
MIRAGE Shield — Honeypot Injector
Injects high-fidelity deception layers into cloned websites:
  • Fake admin / WordPress / phpMyAdmin portals with credential harvesting
  • Fake .env, .git/config, API keys, and PostgreSQL dumps (honeytokens)
  • Hidden crawler-trap links & behavioral JS tracking beacons
  • Full telemetry logging into MIRAGE Junior's SQLite DB & ScoringEngine
"""

import time
import json
import logging

from mirage_shield.config import SHIELD_PORT

logger = logging.getLogger("MIRAGE.Shield.Injector")


class HoneypotInjector:
    """
    Injects honeytokens, credential traps, and silent tracking beacons
    into cloned target pages and standalone deception routes.
    """

    def __init__(self, db_manager=None, scoring_engine=None, shield_port: int = SHIELD_PORT):
        self.db_manager = db_manager
        self.scoring_engine = scoring_engine
        self.shield_port = shield_port
        self.injected_credentials = []
        self.beacon_logs = []
        self.trap_endpoints = {}
        self._setup_traps()

    def _setup_traps(self):
        """Register high-confidence deception endpoints."""
        self.trap_endpoints = {
            "/admin": self._admin_panel_trap,
            "/admin/login": self._admin_panel_trap,
            "/wp-admin": self._admin_panel_trap,
            "/wp-login.php": self._admin_panel_trap,
            "/administrator": self._admin_panel_trap,
            "/phpmyadmin": self._admin_panel_trap,
            "/pma": self._admin_panel_trap,
            "/.env": self._env_file_trap,
            "/.git/config": self._git_config_trap,
            "/.git": self._git_config_trap,
            "/api/config": self._api_config_trap,
            "/api/keys": self._api_keys_trap,
            "/api/tokens": self._api_keys_trap,
            "/backup.sql": self._database_dump_trap,
            "/database.sql": self._database_dump_trap,
            "/dump.sql": self._database_dump_trap,
            "/debug": self._debug_console_trap,
            "/phpinfo.php": self._phpinfo_trap,
            "/server-status": self._server_status_trap,
            "/robots.txt": self._robots_txt_trap,
        }

    def is_trap_endpoint(self, path: str) -> bool:
        """Check whether the normalized path maps to a trap endpoint."""
        clean = "/" + path.strip("/").lower() if path.strip("/") else "/"
        return clean in self.trap_endpoints

    def serve_trap(self, path: str, request_ip: str,
                   method: str = "GET", post_data: dict = None) -> tuple:
        """
        Serve deception content for a trap endpoint and record telemetry.
        Returns: (body, content_type, status_code)
        """
        clean = "/" + path.strip("/").lower() if path.strip("/") else "/"
        handler = self.trap_endpoints.get(clean)
        if not handler:
            return None, None, None

        self._log_interaction(request_ip, clean, method, post_data)
        return handler(request_ip, method, post_data)

    def capture_form_submission(self, ip: str, path: str, form_data: dict) -> tuple:
        """
        Capture credentials submitted to any cloned HTML login form inside the honeypot.
        """
        username = (
            form_data.get("username")
            or form_data.get("user")
            or form_data.get("email")
            or form_data.get("log")
            or form_data.get("pma_username")
            or "(unknown)"
        )
        password = (
            form_data.get("password")
            or form_data.get("pass")
            or form_data.get("pwd")
            or form_data.get("pma_password")
            or ""
        )
        self.record_credential(ip, username, password, path)
        return self._admin_error_page(), "text/html", 401

    def record_credential(self, ip: str, username: str, password: str, path: str = "/login"):
        """Store captured credential locally and in MIRAGE Junior's database."""
        entry = {
            "ip": ip,
            "username": username,
            "password": password,
            "path": path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.injected_credentials.append(entry)
        if len(self.injected_credentials) > 500:
            self.injected_credentials = self.injected_credentials[-250:]

        logger.warning(f"🔑 SHIELD CAPTURED CREDENTIAL: {ip} → {username}:{password} on {path}")

        if self.db_manager:
            try:
                self.db_manager.log_credential(
                    ip_address=ip,
                    protocol="HTTP",
                    username=username,
                    password=password,
                    success=False,
                )
            except Exception as e:
                logger.error(f"DB credential log error: {e}")

        self._sync_event_to_db(
            ip=ip,
            protocol="HTTP",
            event_type="login_attempt",
            details={"shield": True, "path": path, "username": username},
            threat_pts=15,
            mitre_id="T1110",
        )

    def record_beacon(self, beacon_data: dict, fallback_ip: str = "unknown"):
        """Store behavioral JS telemetry sent from a trapped browser session."""
        beacon_entry = {
            "ip": beacon_data.get("ip") or fallback_ip,
            "page": beacon_data.get("page", "/"),
            "screen": beacon_data.get("screen", ""),
            "timezone": beacon_data.get("timezone", ""),
            "platform": beacon_data.get("platform", ""),
            "mouse_movements": beacon_data.get("mouse_movements", 0),
            "keystrokes": beacon_data.get("keystrokes", 0),
            "clicks": beacon_data.get("clicks", 0),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.beacon_logs.append(beacon_entry)
        if len(self.beacon_logs) > 200:
            self.beacon_logs = self.beacon_logs[-100:]

    def inject_deception_layer(self, html: str, ip: str) -> str:
        """
        Inject invisible crawler traps (hidden honeytoken links) and the silent
        behavioral JS tracking beacon into cloned website HTML.
        """
        crawler_bait = (
            '\n<!-- Internal Metadata -->\n'
            '<div style="position:absolute;left:-9999px;top:-9999px;opacity:0;pointer-events:none;" aria-hidden="true">\n'
            '  <a href="/.env">Environment Secrets</a>\n'
            '  <a href="/admin/login">Legacy Admin Portal</a>\n'
            '  <a href="/backup.sql">Database Backup</a>\n'
            '  <a href="/.git/config">Repository Config</a>\n'
            '</div>\n'
        )
        beacon = self.get_tracking_beacon(ip)
        payload = f"{crawler_bait}{beacon}"

        if "</body>" in html.lower():
            idx = html.lower().rfind("</body>")
            return html[:idx] + payload + html[idx:]
        return html + payload

    def get_tracking_beacon(self, ip: str) -> str:
        """JavaScript beacon injected into honeypot pages to fingerprint attacker browser."""
        safe_ip = str(ip).replace("'", "")
        return f"""
<script>
(function() {{
    var data = {{
        ip: '{safe_ip}',
        page: window.location.pathname,
        referrer: document.referrer,
        screen: screen.width + 'x' + screen.height,
        timezone: (Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'unknown',
        language: navigator.language,
        platform: navigator.platform,
        timestamp: new Date().toISOString(),
        mouse_movements: 0,
        keystrokes: 0,
        clicks: 0
    }};
    document.addEventListener('mousemove', function() {{ data.mouse_movements++; }});
    document.addEventListener('keydown', function() {{ data.keystrokes++; }});
    document.addEventListener('click', function() {{ data.clicks++; }});
    function sendTelemetry() {{
        try {{
            navigator.sendBeacon('/mirage-shield/api/beacon', new Blob([JSON.stringify(data)], {{type: 'application/json'}}));
        }} catch (e) {{}}
    }}
    setTimeout(sendTelemetry, 1500);
    setInterval(sendTelemetry, 10000);
}})();
</script>"""

    def _log_interaction(self, ip: str, path: str, method: str, data: dict = None):
        """Log trap hit to console, honeytoken_triggers table, and events table."""
        logger.warning(f"🪤 SHIELD TRAP TRIGGERED: {ip} → {method} {path}")

        if self.db_manager:
            try:
                self.db_manager.log_honeytoken_trigger(
                    token_name=path,
                    token_type="shield_honeypot",
                    ip_address=ip,
                    process_name="MIRAGE_SHIELD",
                    details=json.dumps({"method": method, "shield": True}),
                )
            except Exception as e:
                logger.error(f"DB honeytoken trigger log error: {e}")

        # Map trap endpoint to MITRE technique & event_type
        is_admin = any(k in path for k in ("admin", "wp-login", "phpmyadmin", "pma"))
        if is_admin and method != "POST":
            event_type = "targeted_recon"
            mitre_id = "T1078.001"
            pts = 15
        elif path == "/robots.txt":
            event_type = "lateral_scan"
            mitre_id = "T1046"
            pts = 10
        elif is_admin and method == "POST":
            # record_credential will log login_attempt separately
            return
        else:
            event_type = "honeytoken_trigger"
            mitre_id = "T1552.001" if any(x in path for x in (".env", ".git", "api")) else "T1083"
            pts = 25

        self._sync_event_to_db(
            ip=ip,
            protocol="HONEYTOKEN",
            event_type=event_type,
            details={"shield": True, "path": path, "method": method},
            threat_pts=pts,
            mitre_id=mitre_id,
        )

    def _sync_event_to_db(self, ip: str, protocol: str, event_type: str,
                          details: dict, threat_pts: int, mitre_id: str):
        """Persist event via DatabaseManager and trigger ScoringEngine safely."""
        if not self.db_manager:
            return
        try:
            self.db_manager.log_event(
                ip_address=ip,
                port=self.shield_port,
                protocol=protocol,
                event_type=event_type,
                details=details,
                threat_pts=threat_pts,
                mitre_id=mitre_id,
            )
            if self.scoring_engine:
                self.scoring_engine.calculate_threat_score(ip)
        except Exception as e:
            logger.error(f"Failed syncing Shield event to DB: {e}")

    # ═══════════════════════════════════════════════════
    # Trap Content Generators
    # ═══════════════════════════════════════════════════

    def _admin_panel_trap(self, ip: str, method: str, data: dict) -> tuple:
        if method == "POST" and data:
            return self.capture_form_submission(ip, "/admin", data)
        return self._admin_login_page(), "text/html", 200

    def _admin_login_page(self) -> str:
        return """<!DOCTYPE html>
<html><head><title>Admin Panel — Login Required</title>
<style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9;
           display:flex; justify-content:center; align-items:center; min-height:100vh; }
    .panel { background:#161b22; border:1px solid #30363d; border-radius:12px;
             padding:40px; width:380px; box-shadow:0 8px 32px rgba(0,0,0,0.5); }
    .panel h2 { color:#58a6ff; margin-bottom:8px; }
    .panel p { color:#8b949e; font-size:13px; margin-bottom:25px; }
    input { width:100%; padding:12px; margin-bottom:12px; background:#0d1117;
            border:1px solid #30363d; border-radius:6px; color:#c9d1d9; font-size:14px; }
    button { width:100%; padding:12px; background:#238636; border:none; border-radius:6px;
             color:#fff; font-size:15px; font-weight:600; cursor:pointer; }
    button:hover { background:#2ea043; }
    .warn { color:#f85149; font-size:11px; margin-top:10px; }
</style></head>
<body>
    <div class="panel">
        <h2>🔒 Admin Panel</h2>
        <p>Restricted access. Authorized personnel only.</p>
        <form method="POST" action="/admin/login">
            <input type="text" name="username" placeholder="Admin Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Authenticate</button>
        </form>
        <p class="warn">⚠️ All login attempts are logged and monitored.</p>
    </div>
</body></html>"""

    def _admin_error_page(self) -> str:
        return """<!DOCTYPE html>
<html><head><title>Authentication Failed</title>
<style>
    body { font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9;
           display:flex; justify-content:center; align-items:center; min-height:100vh; }
    .box { background:#161b22; border:1px solid #f85149; border-radius:12px;
           padding:40px; width:400px; text-align:center; }
    .box h2 { color:#f85149; }
    .box p { color:#8b949e; margin-top:15px; }
    a { color:#58a6ff; }
</style></head>
<body>
    <div class="box">
        <h2>❌ Authentication Failed</h2>
        <p>Invalid credentials. Please verify your username and password.</p>
        <p style="margin-top:20px;"><a href="/admin">Try again</a></p>
        <p style="color:#484f58;font-size:11px;margin-top:20px;">
            Event ID: SEC-""" + str(int(time.time())) + """
        </p>
    </div>
</body></html>"""

    def _env_file_trap(self, ip: str, method: str, data: dict) -> tuple:
        content = """# Application Environment Configuration (Production)
APP_ENV=production
APP_DEBUG=false
APP_SECRET=decoy_app_secret_a8f3e2d1c9b7a6e5

DB_HOST=db-prod-01.internal.corp.net
DB_PORT=5432
DB_NAME=production_main
DB_USER=app_service_account
DB_PASSWORD=Pr0d_S3cur3_P@ssw0rd_2026!

AWS_ACCESS_KEY_ID=AKIA3EXAMPLE7TOKEN
AWS_SECRET_ACCESS_KEY=decoyAwsSecretKeyForHoneypotTrap2026
AWS_DEFAULT_REGION=us-east-1

STRIPE_SECRET_KEY=decoy_stripe_key_2026_honeypot_trap
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_DECOY_SECRET
"""
        return content, "text/plain", 200

    def _git_config_trap(self, ip: str, method: str, data: dict) -> tuple:
        content = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://deploy-bot:decoy_git_token_2026@gitlab.corp.internal/web-team/prod-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = deploy-bot
    email = deploy@corp.internal
"""
        return content, "text/plain", 200

    def _api_config_trap(self, ip: str, method: str, data: dict) -> tuple:
        config = {
            "api_version": "v3.2.1",
            "environment": "production",
            "database": {
                "host": "db-prod-01.internal.corp.net",
                "port": 5432,
                "name": "production_main",
                "user": "api_read_write",
                "password": "Pr0d_DB_2026_S3cur3!",
            },
            "auth": {"jwt_secret": "decoy_jwt_secret_key_2026", "token_expiry": 3600},
        }
        return json.dumps(config, indent=2), "application/json", 200

    def _api_keys_trap(self, ip: str, method: str, data: dict) -> tuple:
        keys = {
            "status": "active",
            "keys": [
                {"name": "Production API", "key": "decoy_api_public_2026_honeypot"},
                {"name": "Internal Service", "key": "decoy_internal_a8f3e2d1c9b7a6e5"},
            ],
        }
        return json.dumps(keys, indent=2), "application/json", 200

    def _database_dump_trap(self, ip: str, method: str, data: dict) -> tuple:
        content = """-- PostgreSQL Database Dump (Decoy)
CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255), password_hash VARCHAR(255), role VARCHAR(50));
INSERT INTO users VALUES (1, 'admin@corp.com', '$2b$12$LJ3m4ys3Gz.decoy.hash.admin', 'superadmin');
INSERT INTO users VALUES (2, 'cto@corp.com', '$2b$12$Kx9d8ws2Hy.decoy.hash.cto01', 'admin');
"""
        return content, "text/plain", 200

    def _debug_console_trap(self, ip: str, method: str, data: dict) -> tuple:
        return """<!DOCTYPE html>
<html><head><title>Debug Console</title>
<style>body{background:#1a1a2e;color:#0f0;font-family:monospace;padding:30px;}
pre{background:#0d0d1a;padding:20px;border:1px solid #333;border-radius:8px;}</style></head>
<body><h1 style="color:#e94560;">⚠️ Debug Console — PRODUCTION</h1>
<pre>Server: nginx/1.24.0 | Python 3.11 | DB=postgresql://app:Pr0d_P@ss@db-prod:5432/main
AWS_KEY=AKIA3EXAMPLE7TOKEN | Active Sessions: 847</pre></body></html>""", "text/html", 200

    def _phpinfo_trap(self, ip: str, method: str, data: dict) -> tuple:
        return """<!DOCTYPE html><html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 8.2.12</h1>
<p>System: Linux web-prod-01 | Document Root: /var/www/html/production | DB: db-prod-01.internal:5432</p>
</body></html>""", "text/html", 200

    def _server_status_trap(self, ip: str, method: str, data: dict) -> tuple:
        return f"""<!DOCTYPE html><html><head><title>Apache Server Status</title></head>
<body><h1>Apache Server Status for web-prod-01.corp.internal</h1>
<p>Current Time: {time.strftime("%A, %d-%b-%Y %H:%M:%S %Z")}<br>
Server uptime: 47 days | Total accesses: 2847291</p></body></html>""", "text/html", 200

    def _robots_txt_trap(self, ip: str, method: str, data: dict) -> tuple:
        content = """User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/config
Disallow: /api/keys
Disallow: /backup.sql
Disallow: /.env
Disallow: /.git/
Disallow: /debug
"""
        return content, "text/plain", 200

    def get_captured_credentials(self) -> list:
        return self.injected_credentials[-50:][::-1]

    def get_beacons(self) -> list:
        return self.beacon_logs[-50:][::-1]
