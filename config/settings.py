import os

# === Network Configuration ===
HTTP_PORT = int(os.getenv("MIRAGE_HTTP_PORT", 8080))
SSH_PORT = int(os.getenv("MIRAGE_SSH_PORT", 2222))
FTP_PORT = int(os.getenv("MIRAGE_FTP_PORT", 2121))
DASHBOARD_PORT = int(os.getenv("MIRAGE_DASHBOARD_PORT", 5000))

# === Telegram Configuration ===
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# === Geolocation ===
GEO_API_URL = "http://ip-api.com/json/{ip}"
GEO_CACHE_DURATION = 3600  # seconds

# === Threat Scoring ===
QUARANTINE_THRESHOLD = 76
QUARANTINE_DURATION = 3600  # seconds (1 hour)
SCORING_RULES_FILE = os.path.join("config", "scoring_rules.json")

# === Database ===
DATABASE_PATH = os.path.join("database", "mirage_junior.db")

# === Bait Monitor ===
BAIT_DIRECTORY = "bait"
