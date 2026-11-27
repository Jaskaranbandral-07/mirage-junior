"""
MIRAGE Shield — Synthetic Useless Data Circulation Engine
Absorbs SQLi, API scraping, traversal, RCE, and recon probes at the Shield layer
and feeds attackers realistic-looking yet 100% synthetic/useless decoy payloads
so real customer backends and databases are never exposed.
"""

import hashlib
import json
import random
import time


class SyntheticDeceptionEngine:
    """Generates convincing, worthless synthetic data traps for hostile traffic."""

    _DECOY_NAMES = [
        ("Aarav Mehta", "aarav.mehta@corp-sandbox.invalid", "billing_ops"),
        ("Elena Vance", "elena.vance@corp-sandbox.invalid", "platform_admin"),
        ("Marcus Chen", "marcus.chen@corp-sandbox.invalid", "support_lead"),
        ("Priya Nair", "priya.nair@corp-sandbox.invalid", "devops_readonly"),
        ("Lucas Weber", "lucas.weber@corp-sandbox.invalid", "finance_audit"),
        ("Sana Kapoor", "sana.kapoor@corp-sandbox.invalid", "qa_automation"),
    ]

    def generate_response(self, path: str, attack_types: list,
                          ip: str = "0.0.0.0", domain: str = "protected-site.local") -> tuple:
        """
        Produce a deceptive HTTP response tailored to the attacker's probe.
        Returns: (body_str, content_type, status_code, fake_records_count)
        """
        norm = "/" + (path or "").strip("/").lower() if (path or "").strip("/") else "/"
        attack_types = attack_types or []

        if "directory_traversal" in attack_types or "etc/passwd" in norm or "win.ini" in norm:
            return self._fake_traversal_response(norm)

        if "command_injection" in attack_types or norm in ("/shell", "/cmd", "/exec"):
            return self._fake_rce_response(domain)

        if "sql_injection" in attack_types:
            return self._fake_sqli_dump(domain, ip)

        if norm.startswith("/api") or "graphql" in norm or "json" in norm or "export" in norm:
            return self._fake_api_records(norm, domain, ip)

        # Generic absorbed recon response with canary links
        return self._fake_generic_decoy(norm, domain)

    def _seed_rng(self, *parts) -> random.Random:
        digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
        return random.Random(int(digest[:12], 16))

    def _fake_api_records(self, path: str, domain: str, ip: str) -> tuple:
        rng = self._seed_rng(path, domain, ip)
        records = []
        for idx in range(1, 7):
            name, email, role = self._DECOY_NAMES[(idx + rng.randint(0, 5)) % len(self._DECOY_NAMES)]
            tok = hashlib.md5(f"decoy-{domain}-{idx}-{rng.randint(100,999)}".encode()).hexdigest()[:16]
            records.append({
                "id": f"usr_decoy_{1040 + idx}",
                "name": name,
                "email": email,
                "role": role,
                "api_token": f"sk_decoy_invalid_{tok}",
                "card_last4": f"{rng.randint(1000, 9999)}",
                "account_balance_usd": round(rng.uniform(120.5, 4950.0), 2),
                "internal_sync_url": f"https://{domain}/.env?ref=usr_{idx}",
            })
        payload = {
            "status": "ok",
            "source": f"replica-cache.{domain}",
            "page": 1,
            "per_page": len(records),
            "next_cursor": f"cur_decoy_{int(time.time())}",
            "data": records,
        }
        return json.dumps(payload, indent=2), "application/json", 200, len(records)

    def _fake_sqli_dump(self, domain: str, ip: str) -> tuple:
        rng = self._seed_rng("sqli", domain, ip)
        rows = []
        for idx, (name, email, role) in enumerate(self._DECOY_NAMES[:5], 1):
            fake_hash = hashlib.sha256(f"decoy-pw-{idx}-{domain}".encode()).hexdigest()[:32]
            rows.append({
                "user_id": idx,
                "username": email.split("@")[0],
                "email": email,
                "role": role,
                "password_bcrypt": f"$2b$12$DECOY{fake_hash}",
                "session_secret": f"sess_worthless_{rng.randint(100000, 999999)}",
            })
        payload = {
            "query_status": "rows_returned",
            "db_engine": "PostgreSQL 15.4 (Read-Replica)",
            "row_count": len(rows),
            "rows": rows,
        }
        return json.dumps(payload, indent=2), "application/json", 200, len(rows)

    def _fake_traversal_response(self, path: str) -> tuple:
        if "win.ini" in path:
            body = (
                "; for 16-bit app support\n"
                "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"
                "[MIRAGE_DECOY_HOST]\napp_root=C:\\srv\\decoy-sandbox\\app\n"
            )
        else:
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "mirage_app:x:1001:1001:App Service:/home/mirage_app:/bin/bash\n"
                "backup_svc:x:1002:1002:Backup Sync:/var/backups/.env:/bin/sh\n"
            )
        return body, "text/plain", 200, 5

    def _fake_rce_response(self, domain: str) -> tuple:
        body = (
            f"Linux prod-node-02.{domain} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
            "uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),27(sudo)\n"
            "ENV_CONFIG=/opt/app/.env\n"
            "BACKUP_ARCHIVE=/var/backups/backup.sql\n"
        )
        return body, "text/plain", 200, 4

    def _fake_generic_decoy(self, path: str, domain: str) -> tuple:
        payload = {
            "service": domain,
            "endpoint": path,
            "status": "degraded_cache",
            "debug_links": ["/.env", "/api/config", "/backup.sql", "/admin/login"],
            "token_hint": "decoy_session_invalid_0000",
        }
        return json.dumps(payload, indent=2), "application/json", 200, 1
