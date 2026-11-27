"""
MIRAGE Shield SDK Adapter for NovaPay Demo Target Website.

Uses the parent repo's `mirage_shield.sdk.python_shield` and
`SyntheticDeceptionEngine` when running inside the mono-repo, with a
self-contained fallback so `demo_target/` also runs and deploys standalone
(e.g. as an independent second Vercel project).
"""

from collections import deque
import hashlib
import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import unquote_plus

_PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isdir(os.path.join(_PARENT_DIR, "mirage_shield")) and _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

try:
    from mirage_shield.sdk.python_shield import inspect_request_payload as _core_inspect
    from mirage_shield.synthetic_deception import SyntheticDeceptionEngine as _CoreDeception
except ImportError:
    _core_inspect = None
    _CoreDeception = None


class _FallbackDeceptionEngine:
    """Self-contained synthetic decoy generator when demo_target runs standalone."""

    _DECOY_NAMES = [
        ("Aarav Mehta", "aarav.mehta@corp-sandbox.invalid", "billing_ops"),
        ("Elena Vance", "elena.vance@corp-sandbox.invalid", "platform_admin"),
        ("Marcus Chen", "marcus.chen@corp-sandbox.invalid", "support_lead"),
        ("Priya Nair", "priya.nair@corp-sandbox.invalid", "devops_readonly"),
    ]

    def generate_response(self, path: str, attack_types: list,
                          ip: str = "0.0.0.0", domain: str = "novapay.demo") -> tuple:
        norm = "/" + (path or "").strip("/").lower() if (path or "").strip("/") else "/"
        attack_types = attack_types or []

        if "directory_traversal" in attack_types or "etc/passwd" in norm or "win.ini" in norm:
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "mirage_decoy:x:1001:1001:Sandbox Decoy Account:/home/decoy:/bin/false\n"
                f"# synthetic trace for {norm}\n"
            )
            return body, "text/plain; charset=utf-8", 200, 2

        if "command_injection" in attack_types or norm in ("/shell", "/cmd", "/exec"):
            return "uid=1001(sandbox_decoy) gid=1001(sandbox_decoy)\n", "text/plain; charset=utf-8", 200, 1

        if "/.env" in norm or "/.git" in norm or "config" in norm:
            body = (
                "APP_NAME=NovaPay-Sandbox-Decoy\n"
                "DB_HOST=10.240.0.99\n"
                "DB_PASS=decoy_not_a_real_password_991\n"
                "STRIPE_SECRET=sk_decoy_invalid_0000000000\n"
                "AWS_ACCESS_KEY_ID=AKIADECOYSANDBOX0000\n"
            )
            return body, "text/plain; charset=utf-8", 200, 5

        rows = []
        for idx, (name, email, role) in enumerate(self._DECOY_NAMES, 1):
            h = hashlib.sha256(f"{idx}-{domain}-{ip}".encode()).hexdigest()[:32]
            rows.append({
                "user_id": idx,
                "name": name,
                "email": email,
                "role": role,
                "api_token": f"sk_decoy_invalid_{h[:16]}",
                "password_bcrypt": f"$2b$12$DECOY{h}",
            })
        payload = {
            "status": "ok",
            "source": f"replica-cache.{domain}",
            "row_count": len(rows),
            "rows": rows,
        }
        return json.dumps(payload, indent=2), "application/json", 200, len(rows)


def _fallback_inspect(path: str, method: str, user_agent: str,
                      query_string: str = "", body: str = "") -> tuple:
    score = 0
    attack_types = []
    ua_low = (user_agent or "").lower()
    path_low = unquote_plus(path or "/").lower()
    combined = f"{query_string} {body} {path}"
    combined_up = f"{combined} {unquote_plus(combined)}".upper()

    if any(t in ua_low for t in ("sqlmap", "nikto", "nmap", "hydra", "nuclei", "curl/", "python-requests")):
        score += 25
    if any(tp in path_low for tp in ("/.env", "/.git", "/wp-login.php", "/phpmyadmin", "/admin/login", "/backup.sql", "/etc/passwd")):
        score += 45
        attack_types.append("targeted_recon")
    if any(s in combined_up for s in ("' OR ", "\" OR ", "UNION SELECT", "1=1", "1' OR '1'='1", "'; DROP ", "SLEEP(", "INFORMATION_SCHEMA")):
        score += 50
        attack_types.append("sql_injection")
    if any(s in combined_up for s in ("../", "..\\", "%2E%2E/", "/ETC/PASSWD", "WIN.INI")):
        score += 50
        attack_types.append("directory_traversal")
    if any(s in combined_up for s in ("; CAT ", "| WHOAMI", "&& WHOAMI", "$(WHOAMI)", "`ID`", "/BIN/SH")):
        score += 50
        attack_types.append("command_injection")
    if any(s in combined_up for s in ("<SCRIPT", "JAVASCRIPT:", "ONERROR=", "ALERT(")):
        score += 45
        attack_types.append("xss_probe")

    final_score = min(100, score)
    if final_score >= 80:
        return "BLOCK", final_score, attack_types
    if final_score >= 40:
        return "REDIRECT", final_score, attack_types
    return "ALLOW", final_score, attack_types


def inspect_request(path: str, method: str, user_agent: str,
                    query_string: str = "", body: str = "") -> tuple:
    if _core_inspect is not None:
        return _core_inspect(path, method, user_agent, query_string, body)
    return _fallback_inspect(path, method, user_agent, query_string, body)


class NovaPayShieldMiddleware:
    """
    WSGI protection layer on the NovaPay demo startup app.
    Absorbs attacks before NovaPay business logic runs, serves synthetic decoy
    responses, and auto-provisions/ingests telemetry into MIRAGE Shield.
    """

    def __init__(self, wsgi_app, shield_url: str, site_key: str = "",
                 domain: str = "novapay-demo.local"):
        self.wsgi_app = wsgi_app
        self.shield_url = (shield_url or "").rstrip("/")
        self.site_key = (site_key or "").strip()
        self.site_id = ""
        self.domain = domain
        self.deception = _CoreDeception() if _CoreDeception is not None else _FallbackDeceptionEngine()
        self.recent_absorbed = deque(maxlen=25)
        self._lock = threading.Lock()

    def ensure_registered(self, target_origin: str) -> str:
        """Auto-register NovaPay on MIRAGE Shield if no site_key exists yet."""
        if not self.shield_url:
            return ""
        with self._lock:
            if self.site_key:
                return self.site_key
            return self._register_sync(target_origin)

    def _register_sync(self, target_origin: str) -> str:
        try:
            body = json.dumps({
                "target_url": target_origin or f"https://{self.domain}",
                "owner_name": "NovaPay FinTech (Demo Startup)",
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.shield_url}/api/sites/register",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("api_key"):
                self.site_key = data["api_key"]
                self.site_id = data.get("site_id", "")
                return self.site_key
        except Exception:
            pass
        return ""

    def _post_ingest(self, payload: dict, target_origin: str):
        if not self.shield_url:
            return
        key = self.ensure_registered(target_origin)
        if not key:
            return

        def _send_once(active_key: str):
            req = urllib.request.Request(
                f"{self.shield_url}/api/ingest",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-MIRAGE-Site-Key": active_key,
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3).close()

        try:
            _send_once(key)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                # MIRAGE serverless /tmp DB may have cold-started; re-register & retry once
                with self._lock:
                    self.site_key = ""
                    new_key = self._register_sync(target_origin)
                if new_key:
                    try:
                        _send_once(new_key)
                    except Exception:
                        pass
        except Exception:
            pass

    def ship_telemetry(self, payload: dict, target_origin: str):
        sync_mode = bool(os.getenv("VERCEL") or os.getenv("MIRAGE_SYNC_INGEST"))
        if sync_mode:
            self._post_ingest(payload, target_origin)
        else:
            threading.Thread(target=self._post_ingest, args=(payload, target_origin), daemon=True).start()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/") or "/"
        method = environ.get("REQUEST_METHOD", "GET")
        ua = environ.get("HTTP_USER_AGENT", "")
        qs = environ.get("QUERY_STRING", "")
        ip = (
            environ.get("HTTP_X_MIRAGE_CLIENT_IP", "").strip()
            or environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", "127.0.0.1")
        )

        # Read request body cleanly while preserving stream if legitimate
        raw_body = b""
        if method in ("POST", "PUT", "PATCH"):
            try:
                content_len = int(environ.get("CONTENT_LENGTH") or 0)
            except (ValueError, TypeError):
                content_len = 0
            if 0 < content_len <= 16384 and environ.get("wsgi.input") is not None:
                raw_body = environ["wsgi.input"].read(content_len)
                environ["wsgi.input"] = io.BytesIO(raw_body)
                environ["CONTENT_LENGTH"] = str(len(raw_body))

        body_text = raw_body.decode("utf-8", errors="ignore")
        decision, score, attack_types = inspect_request(path, method, ua, qs, body_text)

        # Never interfere with NovaPay's own Shield status/config helper endpoints unless malicious
        if decision == "ALLOW" or path in ("/api/shield-status", "/api/shield-config"):
            return self.wsgi_app(environ, start_response)

        scheme = environ.get("wsgi.url_scheme", "http")
        host = environ.get("HTTP_HOST", self.domain)
        target_origin = os.getenv("NOVAPAY_PUBLIC_URL") or f"{scheme}://{host}"

        body_str, content_type, status_code, fake_count = self.deception.generate_response(
            path=path, attack_types=attack_types, ip=ip, domain=host.split(":")[0]
        )
        if decision == "BLOCK":
            status_code = 403
            content_type = "application/json"
            body_str = json.dumps({
                "error": "Forbidden — Blocked by MIRAGE Shield",
                "incident_score": score,
                "decoy_reference": f"ms_blk_{ip}",
            }, indent=2)
            fake_count = 0

        captured_user = ""
        captured_pass = ""
        if body_text and method == "POST":
            try:
                parsed_body = json.loads(body_text)
                if isinstance(parsed_body, dict):
                    captured_user = str(parsed_body.get("email") or parsed_body.get("username") or parsed_body.get("log") or "")[:120]
                    captured_pass = str(parsed_body.get("password") or parsed_body.get("pwd") or "")[:120]
            except Exception:
                pass

        self.recent_absorbed.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "ip": ip,
            "path": path,
            "method": method,
            "decision": decision,
            "score": score,
            "attack_types": attack_types,
            "fake_records_served": fake_count,
        })

        self.ship_telemetry({
            "ip": ip,
            "path": path,
            "method": method,
            "user_agent": ua[:160],
            "score": score,
            "decision": decision,
            "attack_types": attack_types,
            "fake_records_served": fake_count,
            "username": captured_user,
            "password": captured_pass,
            "source": "novapay_demo_sdk",
        }, target_origin)

        body_bytes = body_str.encode("utf-8")
        status_text = f"{status_code} {'Forbidden' if status_code == 403 else 'OK'}"
        start_response(status_text, [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body_bytes))),
            ("X-Protected-By", "MIRAGE-Shield"),
            ("X-MIRAGE-Decision", decision),
            ("X-MIRAGE-Score", str(score)),
            ("X-MIRAGE-Fake-Records", str(fake_count)),
        ])
        return [body_bytes]
