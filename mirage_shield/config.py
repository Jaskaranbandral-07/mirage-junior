"""
MIRAGE Shield — Configuration
Central configuration for the Deception-as-a-Service middleware.
"""

import os

# ─── Shield Network Settings ───────────────────────────────
SHIELD_HOST = os.environ.get("SHIELD_HOST", "0.0.0.0")
SHIELD_PORT = int(os.environ.get("MIRAGE_SHIELD_PORT", os.environ.get("SHIELD_PORT", 8443)))

# ─── Target Website (the REAL site to protect) ─────────────
DEFAULT_HTTP_PORT = os.environ.get("MIRAGE_HTTP_PORT", "8080")
TARGET_URL = os.environ.get("SHIELD_TARGET_URL", os.environ.get("SHIELD_TARGET", f"http://127.0.0.1:{DEFAULT_HTTP_PORT}"))

# ─── Clone Storage (Vercel uses read-only FS except /tmp) ──
if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    CLONE_DIR = os.environ.get("SHIELD_CLONE_DIR", "/tmp/mirage_cloned_sites")
else:
    CLONE_DIR = os.environ.get("SHIELD_CLONE_DIR", os.path.join(os.path.dirname(__file__), "cloned_sites"))

# ─── Traffic Analysis Thresholds ───────────────────────────
RATE_LIMIT_WINDOW = 60          # seconds
RATE_LIMIT_MAX_REQUESTS = 30    # max requests per window before flagging
SUSPICION_THRESHOLD = 40        # score >= 40 → redirect to honeypot clone
BLOCK_THRESHOLD = 80            # score >= 80 → block connection + quarantine IP

# Inspect localhost traffic by default so local demos/evaluations trigger Shield
INSPECT_LOCALHOST = os.environ.get("SHIELD_INSPECT_LOCALHOST", "true").lower() in ("1", "true", "yes")
STICKY_HONEYPOT_SESSION = True  # Once diverted to clone, keep attacker inside clone

# ─── Known Malicious User Agents (Attack Tools) ───────────
MALICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wfuzz", "ffuf", "hydra", "medusa", "burpsuite", "zaproxy",
    "nuclei", "httpx", "subfinder", "amass", "whatweb", "wpscan",
    "joomscan", "droopescan", "skipfish", "arachni", "w3af",
    "havij", "acunetix", "netsparker", "appscan", "qualys",
    "openvas", "nessus", "metasploit", "cobalt", "empire",
    "python-requests", "go-http-client", "curl/", "wget/",
]

# ─── High-Risk Paths (Immediate Honeypot Diversion: +40) ───
HIGH_RISK_PATHS = [
    "/.env", "/.git", "/.svn", "/.htaccess", "/.htpasswd",
    "/wp-login.php", "/wp-admin", "/wp-content/uploads",
    "/administrator", "/admin", "/phpmyadmin", "/pma",
    "/api/config", "/api/keys", "/api/credentials", "/api/tokens",
    "/config.php", "/config.yml", "/config.json",
    "/backup", "/backup.sql", "/database.sql", "/dump.sql",
    "/etc/passwd", "/etc/shadow", "/proc/self",
    "/phpinfo.php", "/server-status", "/server-info",
    "/debug", "/console", "/shell", "/cmd",
]

# ─── Reconnaissance Paths (+20 pts) ────────────────────────
RECON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/xmlrpc.php", "/trace", "/.DS_Store",
    "/actuator", "/swagger", "/api-docs", "/graphql",
    "/.well-known", "/cgi-bin",
]

SUSPICIOUS_PATHS = HIGH_RISK_PATHS + RECON_PATHS

# ─── SQL Injection Patterns ───────────────────────────────
SQLI_PATTERNS = [
    "' OR ", "\" OR ", "' AND ", "\" AND ",
    "UNION SELECT", "UNION ALL SELECT",
    "1=1", "1' OR '1'='1", "1\" OR \"1\"=\"1", "ADMIN'--", "'--",
    "' DROP TABLE", "'; DROP ", "'; EXEC ",
    "WAITFOR DELAY", "BENCHMARK(", "SLEEP(",
    "ORDER BY 1", "GROUP BY 1", "HAVING 1=1",
    "LOAD_FILE(", "INTO OUTFILE", "INTO DUMPFILE",
    "INFORMATION_SCHEMA", "@@VERSION", "@@HOSTNAME",
]

# ─── XSS Patterns ─────────────────────────────────────────
XSS_PATTERNS = [
    "<SCRIPT", "JAVASCRIPT:", "ONERROR=", "ONLOAD=",
    "ONFOCUS=", "ONMOUSEOVER=", "ONCLICK=", "ONSUBMIT=",
    "ALERT(", "PROMPT(", "CONFIRM(", "EVAL(",
    "DOCUMENT.COOKIE", "DOCUMENT.LOCATION", "WINDOW.LOCATION",
    "STRING.FROMCHARCODE", "ATOB(", "BTOA(",
]

# ─── Path Traversal Patterns ──────────────────────────────
TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e/", "%2e%2e\\",
    "....//", "..;/", "%00", "%0a", "%0d",
    "/etc/passwd", "/etc/shadow", "win.ini",
]

# ─── Command Injection Patterns ───────────────────────────
CMD_INJECTION_PATTERNS = [
    "; cat ", "; ls", "| whoami", "| id", "&& whoami",
    "&& cat ", "$(whoami)", "$(id)", "`whoami`", "`id`",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
]

# ─── Whitelisted CIDRs (Exempt when INSPECT_LOCALHOST=False) ─
WHITELISTED_CIDRS = [
    "127.0.0.1/32",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
