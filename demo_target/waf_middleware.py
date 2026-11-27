"""
Silent WSGI Security & Deception Middleware for NovaPay.

Protects NovaPay routes silently in the background with zero UI or brand
modifications: legitimate traffic passes directly to NovaPay's real handlers,
while SQLi, secret probing, traversal, and RCE probes are absorbed before
execution, returned realistic useless sandbox payloads, and logged remotely.
"""

import hashlib
import io
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs, unquote_plus

_PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isdir(os.path.join(_PARENT_DIR, "mirage_shield")) and _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

try:
    from mirage_shield.sdk.python_shield import inspect_request_payload as _core_inspect
    from mirage_shield.synthetic_deception import SyntheticDeceptionEngine as _CoreDeception
except ImportError:
    _core_inspect = None
    _CoreDeception = None


class _StandaloneDecoyEngine:
    """Self-contained decoy generator when `demo_target/` deploys standalone on Vercel."""

    _DECOY_ROWS = [
        ("Aarav Mehta", "aarav.mehta@corp-sandbox.invalid", "billing_ops"),
        ("Elena Vance", "elena.vance@corp-sandbox.invalid", "platform_admin"),
        ("Marcus Chen", "marcus.chen@corp-sandbox.invalid", "support_lead"),
        ("Priya Nair", "priya.nair@corp-sandbox.invalid", "devops_readonly"),
    ]

    def generate_response(self, path: str, attack_types: list,
                          ip: str = "0.0.0.0", domain: str = "demotarget.vercel.app") -> tuple:
        norm = "/" + (path or "").strip("/").lower() if (path or "").strip("/") else "/"
        attack_types = attack_types or []

        if "directory_traversal" in attack_types or "etc/passwd" in norm or "win.ini" in norm:
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "app_svc:x:1001:1001:App Sandbox:/home/app_svc:/bin/false\n"
            )
            return body, "text/plain; charset=utf-8", 200, 4

        if "command_injection" in attack_types or norm in ("/shell", "/cmd", "/exec"):
            return "uid=1001(deploy) gid=1001(deploy) groups=1001(deploy)\n", "text/plain; charset=utf-8", 200, 1

        if any(tok in norm for tok in ("/.env", "/.git", "backup.sql", "dump.sql")):
            body = (
                f"# Environment Snapshot ({domain})\n"
                "APP_ENV=production\n"
                f"DB_HOST=db-replica.{domain}\n"
                "DB_USER=decoy_ro\n"
                "DB_PASSWORD=decoy_not_a_real_password_991\n"
                "STRIPE_SECRET_KEY=sk_decoy_invalid_0000000000\n"
                "AWS_ACCESS_KEY_ID=AKIADECOYSANDBOX0000\n"
            )
            return body, "text/plain; charset=utf-8", 200, 6

        rows = []
        for idx, (name, email, role) in enumerate(self._DECOY_ROWS, 1):
            h = hashlib.sha256(f"{idx}-{domain}-{ip}".encode()).hexdigest()[:32]
            rows.append({
                "user_id": idx,
                "username": email.split("@")[0],
                "email": email,
                "role": role,
                "password_bcrypt": f"$2b$12$DECOY{h}",
                "session_secret": f"sess_decoy_{h[:12]}",
            })
        payload = {
            "status": "ok",
            "source": f"replica-cache.{domain}",
            "row_count": len(rows),
            "rows": rows,
        }
        return json.dumps(payload, indent=2), "application/json", 200, len(rows)


def _standalone_inspect(path: str, method: str, user_agent: str,
                        query_string: str = "", body: str = "") -> tuple:
    score = 0
    attack_types = []
    ua_low = (user_agent or "").lower()
    path_low = unquote_plus(path or "/").lower()
    combined = f"{query_string} {body} {path}"
    combined_up = f"{combined} {unquote_plus(combined)}".upper()

    if any(t in ua_low for t in ("sqlmap", "nikto", "nmap", "masscan", "hydra", "nuclei", "curl/", "python-requests")):
        score += 25
    if any(tp in path_low for tp in ("/.env", "/.git", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/admin/login", "/api/config", "/api/keys", "/backup.sql", "/dump.sql", "/phpinfo.php", "/debug", "/etc/passwd")):
        score += 45
        attack_types.append("targeted_recon")
    if any(s in combined_up for s in ("' OR ", "\" OR ", "UNION SELECT", "1=1", "1' OR '1'='1", "'; DROP ", "SLEEP(", "INFORMATION_SCHEMA")):
        score += 50
        attack_types.append("sql_injection")
    if any(s in combined_up for s in ("../", "..\\", "%2E%2E/", "/ETC/PASSWD", "WIN.INI")):
        score += 50
        attack_types.append("directory_traversal")
    if any(s in combined_up for s in ("; CAT ", "| WHOAMI", "&& WHOAMI", "$(WHOAMI)", "`ID`", "/BIN/SH", "POWERSHELL")):
        score += 50
        attack_types.append("command_injection")
    if any(s in combined_up for s in ("<SCRIPT", "JAVASCRIPT:", "ONERROR=", "ONLOAD=", "ALERT(", "DOCUMENT.COOKIE")):
        score += 45
        attack_types.append("xss_probe")

    final_score = min(100, score)
    if final_score >= 80:
        return "BLOCK", final_score, attack_types
    if final_score >= 40:
        return "REDIRECT", final_score, attack_types
    return "ALLOW", final_score, attack_types


def _extract_creds(body_text: str) -> tuple:
    if not body_text:
        return "", ""
    try:
        parsed = json.loads(body_text)
        if isinstance(parsed, dict):
            return (
                str(parsed.get("email") or parsed.get("username") or parsed.get("log") or "")[:120],
                str(parsed.get("password") or parsed.get("pwd") or "")[:120],
            )
    except Exception:
        pass
    try:
        form = parse_qs(body_text, keep_blank_values=False)
        return (
            str((form.get("email") or form.get("username") or form.get("log") or [""])[0])[:120],
            str((form.get("password") or form.get("pwd") or [""])[0])[:120],
        )
    except Exception:
        return "", ""


class SilentBackendWAF:
    """Silent backend protection layer wrapping NovaPay's WSGI app."""

    def __init__(self, wsgi_app, telemetry_url: str = "", site_key: str = ""):
        self.wsgi_app = wsgi_app
        self.telemetry_url = (telemetry_url or "").rstrip("/")
        self.site_key = (site_key or "").strip()
        self.deception = _CoreDeception() if _CoreDeception is not None else _StandaloneDecoyEngine()
        self._lock = threading.Lock()

    def _register_site_sync(self, origin: str) -> str:
        if not self.telemetry_url:
            return ""
        try:
            body = json.dumps({
                "target_url": origin,
                "owner_name": "NovaPay Cloud Payroll",
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.telemetry_url}/api/sites/register",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("api_key"):
                self.site_key = data["api_key"]
                return self.site_key
        except Exception:
            pass
        return ""

    def _emit_telemetry(self, payload: dict, origin: str):
        if not self.telemetry_url:
            return

        def _post(key: str):
            req = urllib.request.Request(
                f"{self.telemetry_url}/api/ingest",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-MIRAGE-Site-Key": key,
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3).close()

        def _deliver():
            with self._lock:
                key = self.site_key or self._register_site_sync(origin)
            if not key:
                return
            try:
                _post(key)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    with self._lock:
                        self.site_key = ""
                        new_key = self._register_site_sync(origin)
                    if new_key:
                        try:
                            _post(new_key)
                        except Exception:
                            pass
            except Exception:
                pass

        if os.getenv("VERCEL") or os.getenv("MIRAGE_SYNC_INGEST"):
            _deliver()
        else:
            threading.Thread(target=_deliver, daemon=True).start()

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
        inspect_fn = _core_inspect if _core_inspect is not None else _standalone_inspect
        decision, score, attack_types = inspect_fn(path, method, ua, qs, body_text)

        if decision == "ALLOW":
            return self.wsgi_app(environ, start_response)

        scheme = (
            environ.get("HTTP_X_FORWARDED_PROTO", "").split(",")[0].strip()
            or environ.get("wsgi.url_scheme", "http")
        )
        host = environ.get("HTTP_HOST", "demotarget.vercel.app")
        origin = os.getenv("NOVAPAY_PUBLIC_URL") or f"{scheme}://{host}"

        body_str, content_type, status_code, fake_count = self.deception.generate_response(
            path=path, attack_types=attack_types, ip=ip, domain=host.split(":")[0]
        )
        if decision == "BLOCK":
            status_code = 403
            content_type = "application/json"
            body_str = json.dumps({
                "error": "Access Denied — Request Blocked by Security Policy",
                "incident_score": score,
                "reference": f"waf_blk_{ip}",
            }, indent=2)
            fake_count = 0

        captured_user, captured_pass = _extract_creds(body_text) if method == "POST" else ("", "")
        self._emit_telemetry({
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
            "source": "backend_waf_middleware",
        }, origin)

        body_bytes = body_str.encode("utf-8")
        status_text = f"{status_code} {'Forbidden' if status_code == 403 else 'OK'}"
        start_response(status_text, [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body_bytes))),
        ])
        return [body_bytes]
