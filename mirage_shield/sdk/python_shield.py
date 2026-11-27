"""
MIRAGE Shield — Drop-In Customer Backend Middleware (Python WSGI / Flask / FastAPI)

Install on a customer backend to absorb hostile requests BEFORE they hit real
business logic or databases, serve useless synthetic decoy data to attackers,
and stream telemetry to the customer's personal MIRAGE Shield dashboard.

Quick Flask integration (2 lines):
    from mirage_shield.sdk.python_shield import protect_flask_app
    protect_flask_app(app, site_key="ms_live_YOUR_KEY", shield_url="https://mirage-junior.vercel.app")
"""

import io
import json
import os
import threading
import urllib.request
from urllib.parse import parse_qs, unquote_plus

from mirage_shield.synthetic_deception import SyntheticDeceptionEngine

_SCANNER_UAS = (
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wfuzz", "ffuf", "hydra", "nuclei", "wpscan", "acunetix",
    "curl/", "python-requests", "go-http-client",
)
_TRAP_PATHS = (
    "/.env", "/.git", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/admin/login", "/api/config", "/api/keys", "/backup.sql", "/dump.sql",
    "/phpinfo.php", "/debug", "/etc/passwd",
)
_SQLI_SIGS = ("' OR ", "\" OR ", "UNION SELECT", "1=1", "1' OR '1'='1", "'; DROP ", "SLEEP(", "INFORMATION_SCHEMA")
_XSS_SIGS = ("<SCRIPT", "JAVASCRIPT:", "ONERROR=", "ONLOAD=", "ALERT(", "DOCUMENT.COOKIE")
_TRAVERSAL_SIGS = ("../", "..\\", "%2E%2E/", "/ETC/PASSWD", "WIN.INI")
_RCE_SIGS = ("; CAT ", "| WHOAMI", "&& WHOAMI", "$(WHOAMI)", "`ID`", "/BIN/SH", "POWERSHELL")


def inspect_request_payload(path: str, method: str, user_agent: str,
                            query_string: str = "", body: str = "") -> tuple:
    """Lightweight local threat scorer returning (decision, score, attack_types)."""
    score = 0
    attack_types = []
    ua_low = (user_agent or "").lower()
    path_low = unquote_plus(path or "/").lower()
    combined = f"{query_string} {body} {path}"
    combined_up = f"{combined} {unquote_plus(combined)}".upper()

    if any(t in ua_low for t in _SCANNER_UAS):
        score += 25
    if any(tp in path_low for tp in _TRAP_PATHS):
        score += 45
        attack_types.append("targeted_recon")
    if any(s in combined_up for s in _SQLI_SIGS):
        score += 50
        attack_types.append("sql_injection")
    if any(s in combined_up for s in _TRAVERSAL_SIGS):
        score += 50
        attack_types.append("directory_traversal")
    if any(s in combined_up for s in _RCE_SIGS):
        score += 50
        attack_types.append("command_injection")
    if any(s in combined_up for s in _XSS_SIGS):
        score += 45
        attack_types.append("xss_probe")

    final_score = min(100, score)
    if final_score >= 80:
        return "BLOCK", final_score, attack_types
    if final_score >= 40:
        return "REDIRECT", final_score, attack_types
    return "ALLOW", final_score, attack_types


def _extract_post_credentials(body_text: str) -> tuple:
    """Safely extract submitted login identifiers on intercepted POST probes."""
    if not body_text:
        return "", ""
    try:
        parsed = json.loads(body_text)
        if isinstance(parsed, dict):
            user = str(parsed.get("email") or parsed.get("username") or parsed.get("log") or "")[:120]
            pw = str(parsed.get("password") or parsed.get("pwd") or "")[:120]
            return user, pw
    except Exception:
        pass
    try:
        form = parse_qs(body_text, keep_blank_values=False)
        user = str((form.get("email") or form.get("username") or form.get("log") or [""])[0])[:120]
        pw = str((form.get("password") or form.get("pwd") or [""])[0])[:120]
        return user, pw
    except Exception:
        return "", ""


def _post_ingest_once(shield_url: str, site_key: str, payload: dict):
    url = shield_url.rstrip("/") + "/api/ingest"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-MIRAGE-Site-Key": site_key,
        },
        method="POST",
    )
    urllib.request.urlopen(req, timeout=4).close()


def _ship_telemetry(shield_url: str, site_key: str, payload: dict):
    """Ship absorbed telemetry (synchronously on Vercel serverless, async locally)."""
    if not shield_url or not site_key:
        return

    def _send():
        try:
            _post_ingest_once(shield_url, site_key, payload)
        except Exception:
            pass

    if os.getenv("VERCEL") or os.getenv("MIRAGE_SYNC_INGEST"):
        _send()
    else:
        threading.Thread(target=_send, daemon=True).start()


class MirageShieldWSGIMiddleware:
    """Standard WSGI middleware protecting any Flask/Django/Python web backend."""

    def __init__(self, wsgi_app, site_key: str,
                 shield_url: str = "https://mirage-junior.vercel.app",
                 domain: str = "protected-app.local",
                 stealth: bool = False):
        self.wsgi_app = wsgi_app
        self.site_key = site_key
        self.shield_url = shield_url
        self.domain = domain
        self.stealth = stealth
        self.deception = SyntheticDeceptionEngine()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/") or "/"
        method = environ.get("REQUEST_METHOD", "GET")
        ua = environ.get("HTTP_USER_AGENT", "")
        qs = environ.get("QUERY_STRING", "")
        ip = (
            environ.get("HTTP_X_MIRAGE_CLIENT_IP", "").strip()
            or environ.get("HTTP_X_VERCEL_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("HTTP_X_REAL_IP", "").strip()
            or environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", "127.0.0.1")
        )

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
        decision, score, attack_types = inspect_request_payload(path, method, ua, qs, body_text)
        if decision == "ALLOW":
            return self.wsgi_app(environ, start_response)

        # Attack absorbed by Shield — customer backend never runs!
        body_str, content_type, status_code, fake_count = self.deception.generate_response(
            path=path, attack_types=attack_types, ip=ip, domain=self.domain
        )
        if decision == "BLOCK":
            status_code = 403
            content_type = "application/json"
            body_str = json.dumps({
                "error": "Access Denied — Blocked by Security Edge" if self.stealth else "Forbidden — Blocked by MIRAGE Shield",
                "incident_score": score,
                "reference": f"sec_blk_{ip}" if self.stealth else f"ms_blk_{ip}",
            })
            fake_count = 0

        captured_user, captured_pass = _extract_post_credentials(body_text) if method == "POST" else ("", "")

        _ship_telemetry(self.shield_url, self.site_key, {
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
            "source": "python_wsgi_sdk",
        })

        body_bytes = body_str.encode("utf-8")
        status_text = f"{status_code} {'Forbidden' if status_code == 403 else 'OK'}"
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body_bytes))),
        ]
        if not self.stealth:
            headers.append(("X-Protected-By", "MIRAGE-Shield"))
        start_response(status_text, headers)
        return [body_bytes]


def protect_flask_app(app, site_key: str,
                      shield_url: str = "https://mirage-junior.vercel.app",
                      domain: str = "protected-app.local",
                      stealth: bool = False):
    """Wrap a Flask application's WSGI stack with MIRAGE Shield absorption."""
    app.wsgi_app = MirageShieldWSGIMiddleware(
        app.wsgi_app, site_key=site_key, shield_url=shield_url, domain=domain, stealth=stealth
    )
    return app
