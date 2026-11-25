"""
MIRAGE Shield — Reverse Proxy & Deception-as-a-Service Middleware
Sits in front of any website, scores incoming traffic in real-time, routes
normal users to the real site, diverts suspicious actors into a pixel-accurate
cloned honeypot with injected traps, and blocks + quarantines high-risk IPs.
"""

import os
import sys
import time
import json
import logging
import threading
from urllib.parse import urlparse

from flask import (
    Flask, Response, jsonify, redirect,
    render_template, request, send_file
)

# Ensure parent project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mirage_shield.config as shield_cfg
from mirage_shield.traffic_analyzer import TrafficAnalyzer, ALLOW, REDIRECT, BLOCK
from mirage_shield.honeypot_injector import HoneypotInjector
from mirage_shield.site_cloner import SiteCloner

try:
    import requests as http_requests
except ImportError:
    http_requests = None

logger = logging.getLogger("MIRAGE.Shield.Proxy")

# Shared singleton for cross-module visibility (Shield :8443 + Main Dashboard :5000)
_shared_shield_instance = None
_shared_lock = threading.Lock()


def get_shield_instance(target_url: str = None, db_manager=None,
                        scoring_engine=None, quarantine_manager=None):
    """Return the shared ShieldProxy instance, creating it on first call."""
    global _shared_shield_instance
    with _shared_lock:
        if _shared_shield_instance is None:
            _shared_shield_instance = ShieldProxy(
                target_url=target_url,
                db_manager=db_manager,
                scoring_engine=scoring_engine,
                quarantine_manager=quarantine_manager,
            )
        return _shared_shield_instance


def reset_shield_instance():
    """Reset the shared singleton (useful for isolated unit tests)."""
    global _shared_shield_instance
    with _shared_lock:
        _shared_shield_instance = None


class ShieldProxy:
    """
    Reverse proxy server that protects any target website with deception.
    """

    def __init__(self, target_url: str = None, db_manager=None,
                 scoring_engine=None, quarantine_manager=None,
                 auto_init_backend: bool = True):
        self.target_url = (target_url or shield_cfg.TARGET_URL).rstrip("/")
        self.shield_port = shield_cfg.SHIELD_PORT
        self.start_time = time.time()

        # Connect optionally to MIRAGE Junior core DB / Scoring / Quarantine
        self.db_manager = db_manager
        self.scoring_engine = scoring_engine
        self.quarantine_manager = quarantine_manager
        if auto_init_backend:
            self._init_backend_integrations()

        self.analyzer = TrafficAnalyzer()
        self.injector = HoneypotInjector(
            db_manager=self.db_manager,
            scoring_engine=self.scoring_engine,
            shield_port=self.shield_port,
        )
        self.cloner = SiteCloner(self.target_url)
        self.clone_path = None
        self.stats = {
            "total_requests": 0,
            "allowed": 0,
            "redirected": 0,
            "blocked": 0,
            "credentials_captured": 0,
            "honeytokens_triggered": 0,
        }
        self.app = self._create_app()

    def _init_backend_integrations(self):
        """Attach MIRAGE Junior DatabaseManager, ScoringEngine, QuarantineManager safely."""
        try:
            if self.db_manager is None:
                from database.db_setup import init_db
                from database.db_manager import DatabaseManager
                init_db()
                self.db_manager = DatabaseManager()
            if self.quarantine_manager is None:
                from engine.quarantine import QuarantineManager
                self.quarantine_manager = QuarantineManager()
            if self.scoring_engine is None:
                from engine.scoring_engine import ScoringEngine
                self.scoring_engine = ScoringEngine()
        except Exception as e:
            logger.warning(f"Backend DB/Engine integration unavailable (running standalone): {e}")

    def _create_app(self) -> Flask:
        """Build Flask app with management routes registered before catch-all proxy."""
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        app = Flask(__name__, template_folder=template_dir)

        @app.before_request
        def handle_shield_preflight():
            if request.method == "OPTIONS" and request.path.startswith("/mirage-shield/api/"):
                resp = Response("", status=204)
                resp.headers["Access-Control-Allow-Origin"] = "*"
                resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
                return resp

        @app.after_request
        def add_shield_cors(response):
            if request.path.startswith("/mirage-shield/api/"):
                response.headers["Access-Control-Allow-Origin"] = "*"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response

        # ── Management / Command Center Routes ──
        @app.route("/mirage-shield")
        @app.route("/mirage-shield/")
        def shield_root():
            return redirect("/mirage-shield/dashboard")

        @app.route("/mirage-shield/dashboard")
        def shield_dashboard():
            return render_template(
                "shield_dashboard.html",
                target=self.target_url,
                clone_status=self.cloner.last_status,
                inspect_localhost=self.analyzer.inspect_localhost,
            )

        @app.route("/mirage-shield/assets/<path:filename>")
        def shield_asset(filename):
            asset_path = self.cloner.resolve_asset_path(filename)
            if asset_path:
                return send_file(asset_path)
            return Response("Asset not found", status=404)

        @app.route("/mirage-shield/api/stats")
        def shield_stats():
            return jsonify(self.get_full_stats())

        @app.route("/mirage-shield/api/recent")
        def shield_recent():
            return jsonify(self.analyzer.get_recent_analysis(limit=50))

        @app.route("/mirage-shield/api/credentials")
        def shield_credentials():
            return jsonify(self.injector.get_captured_credentials())

        @app.route("/mirage-shield/api/beacons")
        def shield_beacons():
            return jsonify(self.injector.get_beacons())

        @app.route("/mirage-shield/api/beacon", methods=["POST"])
        def shield_beacon_collect():
            data = request.get_json(silent=True)
            if not data:
                try:
                    data = json.loads(request.get_data(as_text=True) or "{}")
                except Exception:
                    data = {}
            self.injector.record_beacon(data, fallback_ip=self._get_client_ip())
            return jsonify({"status": "recorded"})

        @app.route("/mirage-shield/api/unblock/<ip>", methods=["POST"])
        def shield_unblock(ip):
            ok = self.unblock_ip(ip)
            return jsonify({"success": ok, "ip": ip})

        @app.route("/mirage-shield/api/clone", methods=["POST"])
        def shield_clone():
            payload = request.get_json(silent=True) or {}
            new_target = (payload.get("target_url") or "").strip()
            max_pages = int(payload.get("max_pages", 5))
            result = self.switch_and_clone(new_target, max_pages=max_pages)
            status_code = 200 if result.get("success") else 400
            return jsonify(result), status_code

        @app.route("/mirage-shield/api/config", methods=["POST"])
        def shield_config():
            payload = request.get_json(silent=True) or {}
            if "inspect_localhost" in payload:
                self.analyzer.set_inspect_localhost(bool(payload["inspect_localhost"]))
            return jsonify({
                "success": True,
                "inspect_localhost": self.analyzer.inspect_localhost,
                "target_url": self.target_url,
            })

        @app.route("/mirage-shield/api/simulate", methods=["POST"])
        def shield_simulate():
            payload = request.get_json(silent=True) or {}
            scenario = payload.get("scenario", "sqli")
            result = self.run_simulation(scenario)
            return jsonify(result)

        @app.route("/mirage-shield/preview")
        def shield_clone_preview():
            """Allow admin/evaluator to preview the cloned honeypot safely."""
            req_target = (request.args.get("target") or "").strip()
            if req_target and req_target.rstrip("/") != self.target_url.rstrip("/"):
                self.switch_and_clone(req_target, max_pages=2)
            index_path = self.cloner.get_index_path()
            if not os.path.exists(index_path):
                self.cloner.clone(max_pages=3)
            if os.path.exists(index_path):
                with open(index_path, "r", encoding="utf-8") as f:
                    return Response(f.read(), status=200, content_type="text/html")
            return Response("Clone not generated yet", status=404)

        # ── Catch-All Reverse Proxy Route ──
        @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
        @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
        def proxy(path):
            return self._handle_request(path)

        return app

    # ═══════════════════════════════════════════════════
    # Request Inspection & Routing Pipeline
    # ═══════════════════════════════════════════════════

    def _get_client_ip(self) -> str:
        """Extract client IP, supporting reverse proxies / simulation headers."""
        sim_ip = request.headers.get("X-MIRAGE-Client-IP")
        if sim_ip:
            return sim_ip.strip()
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or "127.0.0.1"

    def _handle_request(self, path: str) -> Response:
        """Inspect incoming HTTP traffic and route ALLOW / REDIRECT / BLOCK."""
        self.stats["total_requests"] += 1
        full_path = f"/{path}" if path else "/"

        client_ip = self._get_client_ip()
        user_agent = request.headers.get("User-Agent", "")
        method = request.method
        query_string = request.query_string.decode("utf-8", errors="ignore")
        body = request.get_data(as_text=True)

        decision, score, breakdown = self.analyzer.analyze(
            ip=client_ip,
            path=full_path,
            method=method,
            user_agent=user_agent,
            headers=dict(request.headers),
            query_string=query_string,
            body=body,
        )

        # Record non-benign detections into MIRAGE Junior database
        if decision in (REDIRECT, BLOCK):
            self._sync_detection_to_db(client_ip, full_path, method, score, decision, breakdown, user_agent)

        if decision == BLOCK:
            self.stats["blocked"] += 1
            return self._serve_block_page(client_ip, score)

        if decision == REDIRECT:
            self.stats["redirected"] += 1
            return self._serve_honeypot(client_ip, full_path, method)

        self.stats["allowed"] += 1
        return self._proxy_to_real_site(full_path, method)

    def _proxy_to_real_site(self, path: str, method: str) -> Response:
        """Forward legitimate request cleanly to the protected target website."""
        if not http_requests:
            return Response("Proxy requires the 'requests' library.", status=502)

        parsed_target = urlparse(self.target_url)
        if parsed_target.port == self.shield_port and parsed_target.hostname in ("127.0.0.1", "localhost"):
            return Response("Configuration Error: TARGET_URL points to Shield's own port.", status=500)

        target = f"{self.target_url}{path}"
        try:
            headers = {
                k: v for k, v in request.headers
                if k.lower() not in ("host", "content-length")
            }
            resp = http_requests.request(
                method=method,
                url=target,
                headers=headers,
                data=request.get_data(),
                params=request.args,
                timeout=12,
                allow_redirects=False,
                verify=False,
            )

            excluded = {"content-encoding", "transfer-encoding", "connection"}
            response_headers = [
                (k, v) for k, v in resp.headers.items()
                if k.lower() not in excluded
            ]
            return Response(resp.content, status=resp.status_code, headers=response_headers)
        except Exception as e:
            logger.warning(f"Upstream target unreachable ({target}): {e}")
            return Response(
                f"MIRAGE Shield Proxy: Protected origin ({self.target_url}) is currently unreachable.",
                status=502,
            )

    def _serve_honeypot(self, ip: str, path: str, method: str) -> Response:
        """Serve cloned site + injected honeypot traps to suspicious visitors."""
        # Serve trap endpoint (.env, /admin, /backup.sql, etc.)
        if self.injector.is_trap_endpoint(path):
            self.stats["honeytokens_triggered"] += 1
            post_data = (request.form.to_dict() or request.get_json(silent=True) or None) if method == "POST" else None
            content, content_type, status = self.injector.serve_trap(
                path, ip, method, post_data
            )
            if content is not None:
                if post_data and any(k in post_data for k in ("username", "user", "email", "log", "password", "pass", "pwd", "pma_username", "pma_password")):
                    self.stats["credentials_captured"] += 1
                return Response(content, status=status, content_type=content_type)

        # Capture POST submissions targeting login/auth forms on cloned pages
        if method == "POST":
            form_data = request.form.to_dict() or request.get_json(silent=True) or {}
            if form_data:
                self.stats["credentials_captured"] += 1
                content, content_type, status = self.injector.capture_form_submission(
                    ip, path, form_data
                )
                return Response(content, status=status, content_type=content_type)

        # Resolve cloned HTML page (subpage or index fallback)
        page_file = self.cloner.resolve_page_path(path)
        if not page_file:
            self.cloner.clone(max_pages=3)
            page_file = self.cloner.resolve_page_path(path)

        if page_file and os.path.exists(page_file):
            with open(page_file, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read()
            deceptive_html = self.injector.inject_deception_layer(html, ip)
            return Response(deceptive_html, status=200, content_type="text/html")

        return Response("Service temporarily unavailable", status=503)

    def _serve_block_page(self, ip: str, score: int) -> Response:
        """Return HTTP 403 block notice to high-threat attackers."""
        html = f"""<!DOCTYPE html>
<html><head><title>403 — Access Denied</title>
<style>
    body {{ background:#0a0a0a; color:#ff4444; font-family:monospace;
           display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }}
    .box {{ text-align:center; border:2px solid #ff4444; padding:48px; border-radius:12px;
            background:rgba(255,68,68,0.06); max-width:520px; }}
    .box h1 {{ font-size:56px; margin:0 0 12px 0; }}
    .box h2 {{ color:#ff6666; margin-bottom:16px; }}
    .box p {{ color:#999; font-size:13px; line-height:1.7; }}
    .id {{ color:#555; font-size:11px; margin-top:24px; }}
</style></head>
<body>
    <div class="box">
        <h1>🛡️</h1>
        <h2>ACCESS DENIED — IP QUARANTINED</h2>
        <p>Malicious activity was detected by MIRAGE Shield.<br>
        Your IP has been quarantined and logged for security review.</p>
        <p class="id">
            Threat Score: {score}/100 | Client IP: {ip}<br>
            Incident ID: MIRAGE-{int(time.time())}
        </p>
    </div>
</body></html>"""
        return Response(html, status=403, content_type="text/html")

    def _sync_detection_to_db(self, ip: str, path: str, method: str,
                              score: int, decision: str, breakdown: dict, user_agent: str):
        """Log Shield detections to MIRAGE Junior's database and quarantine manager."""
        attack_types = breakdown.get("attack_types") or []
        if "sql_injection" in attack_types:
            event_type, mitre_id, pts = "sql_injection", "T1190", 20
        elif "directory_traversal" in attack_types:
            event_type, mitre_id, pts = "directory_traversal", "T1083", 15
        elif "command_injection" in attack_types:
            event_type, mitre_id, pts = "shell_command", "T1059", 20
        elif "xss_probe" in attack_types:
            event_type, mitre_id, pts = "targeted_recon", "T1190", 15
        elif breakdown.get("suspicious_path", 0) >= 40:
            event_type, mitre_id, pts = "targeted_recon", "T1552.001", 20
        else:
            event_type, mitre_id, pts = "lateral_scan", "T1046", 15

        if self.db_manager:
            try:
                self.db_manager.log_event(
                    ip_address=ip,
                    port=self.shield_port,
                    protocol="HTTP",
                    event_type=event_type,
                    details={
                        "shield": True,
                        "decision": decision,
                        "shield_score": score,
                        "path": path,
                        "method": method,
                        "user_agent": user_agent[:120],
                    },
                    threat_pts=pts,
                    mitre_id=mitre_id,
                )
                if self.scoring_engine:
                    self.scoring_engine.calculate_threat_score(ip)
                if decision == BLOCK and self.quarantine_manager:
                    self.quarantine_manager.block_ip(
                        ip,
                        reason=f"MIRAGE Shield blocked malicious traffic (score {score}/100)",
                        threat_score=score,
                    )
            except Exception as e:
                logger.error(f"DB sync error in Shield: {e}")

    # ═══════════════════════════════════════════════════
    # Management, Dynamic Cloning & Live Simulation APIs
    # ═══════════════════════════════════════════════════

    def switch_and_clone(self, target_url: str, max_pages: int = 5) -> dict:
        """Switch target website URL and clone it dynamically."""
        if not target_url:
            return {"success": False, "error": "Target URL cannot be empty."}
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        if not parsed.netloc:
            return {"success": False, "error": "Invalid URL provided."}

        self.target_url = target_url.rstrip("/")
        self.cloner.set_target(self.target_url)
        path = self.cloner.clone(max_pages=max_pages)
        return {
            "success": True,
            "target_url": self.target_url,
            "clone_path": path,
            "clone_status": self.cloner.last_status,
        }

    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP in both Shield TrafficAnalyzer and QuarantineManager."""
        ok = self.analyzer.unblock_ip(ip)
        if self.quarantine_manager:
            try:
                self.quarantine_manager.unblock_ip(ip, unblocked_by="shield_manual")
            except Exception:
                pass
        return ok

    def run_simulation(self, scenario: str = "sqli") -> dict:
        """
        Execute a realistic simulated client/attacker scenario through the analyzer
        and injector for live demonstrations (without touching real sites).
        """
        scenarios = {
            "legitimate": {
                "ip": "203.0.113.42",
                "path": "/products",
                "method": "GET",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
                "headers": {"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip"},
                "query": "category=enterprise",
                "body": "",
                "desc": "Normal visitor browsing products → Allowed to Real Site",
            },
            "recon_env": {
                "ip": "185.220.101.99",
                "path": "/.env",
                "method": "GET",
                "ua": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0 Safari/537.36",
                "headers": {"Accept": "*/*"},
                "query": "",
                "body": "",
                "desc": "Attacker probing /.env secrets → Diverted to Honeypot Clone",
            },
            "sqli": {
                "ip": "194.26.29.112",
                "path": "/login",
                "method": "POST",
                "ua": "sqlmap/1.7.11#stable",
                "headers": {},
                "query": "id=1' OR '1'='1'--",
                "body": "username=admin' OR 1=1--&password=pwned",
                "desc": "SQLMap SQL Injection attack → Immediately Blocked & Quarantined",
            },
            "cred_harvest": {
                "ip": "45.155.205.210",
                "path": "/admin/login",
                "method": "POST",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0",
                "headers": {"Accept": "text/html"},
                "query": "",
                "body": "username=ceo@company.com&password=SuperSecret2026!",
                "form": {"username": "ceo@company.com", "password": "SuperSecret2026!"},
                "desc": "Credential stuffing inside cloned /admin → Trapped & Credentials Logged",
            },
        }

        cfg = scenarios.get(scenario, scenarios["sqli"])
        self.stats["total_requests"] += 1

        decision, score, breakdown = self.analyzer.analyze(
            ip=cfg["ip"],
            path=cfg["path"],
            method=cfg["method"],
            user_agent=cfg["ua"],
            headers=cfg["headers"],
            query_string=cfg["query"],
            body=cfg["body"],
        )

        if decision == BLOCK:
            self.stats["blocked"] += 1
            self._sync_detection_to_db(cfg["ip"], cfg["path"], cfg["method"], score, decision, breakdown, cfg["ua"])
        elif decision == REDIRECT:
            self.stats["redirected"] += 1
            self._sync_detection_to_db(cfg["ip"], cfg["path"], cfg["method"], score, decision, breakdown, cfg["ua"])
            if self.injector.is_trap_endpoint(cfg["path"]):
                self.stats["honeytokens_triggered"] += 1
                self.injector.serve_trap(cfg["path"], cfg["ip"], cfg["method"], cfg.get("form"))
                if cfg.get("form"):
                    self.stats["credentials_captured"] += 1
        else:
            self.stats["allowed"] += 1

        return {
            "status": "success",
            "scenario": scenario,
            "description": cfg["desc"],
            "ip": cfg["ip"],
            "decision": decision,
            "score": score,
            "breakdown": breakdown,
        }

    def get_full_stats(self) -> dict:
        stats = self.stats.copy()
        stats["analyzer"] = self.analyzer.get_stats()
        stats["uptime_seconds"] = int(time.time() - self.start_time)
        stats["target_url"] = self.target_url
        stats["clone_status"] = self.cloner.last_status
        stats["credentials_captured"] = max(
            stats["credentials_captured"],
            len(self.injector.injected_credentials),
        )
        return stats

    def clone_target(self):
        """Pre-clone the target website on startup."""
        logger.info(f"🪞 Pre-cloning protected target: {self.target_url}")
        self.clone_path = self.cloner.clone(max_pages=5)
        logger.info(f"✅ Clone ready at: {self.clone_path}")

    def run(self, host: str = None, port: int = None):
        """Start the MIRAGE Shield reverse proxy server."""
        host = host or shield_cfg.SHIELD_HOST
        port = port or self.shield_port

        clone_thread = threading.Thread(target=self.clone_target, daemon=True)
        clone_thread.start()

        logger.info(f"🛡️  MIRAGE Shield Proxy running on http://{host}:{port}")
        logger.info(f"🎯 Protecting Origin: {self.target_url}")
        logger.info(f"📊 Shield Command Center: http://localhost:{port}/mirage-shield/dashboard")

        self.app.run(host=host, port=port, debug=False, use_reloader=False)
