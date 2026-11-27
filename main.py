"""
MIRAGE Shield — Main Entry Point
Multi-Tenant Cyber Deception & Active WAF Platform

Starts the SaaS Dashboard / Customer Ingestion API (:5000),
MIRAGE Shield Reverse Proxy (:8443), and background Quarantine Expiry Checker.
Usage:
    python main.py              # Start full platform + reverse proxy
    python main.py --clean      # Clear telemetry rows before startup
    python main.py --no-shield  # Start dashboard & API only
"""

import logging
import os
import sys
import threading
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("MIRAGE")


def print_banner():
    """Print the MIRAGE Shield ASCII art banner."""
    banner = """
    \033[92m
    ███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
    ████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
    ██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗      ███████╗███████║██║█████╗  ██║     ██║  ██║
    ██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝      ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
    ██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗    ███████║██║  ██║██║███████╗███████╗██████╔╝
    ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
    \033[0m
    \033[96m╔══════════════════════════════════════════════════════════════╗
    ║   MIRAGE Shield — Multi-Tenant Cyber Deception & WAF Suite   ║
    ║      Per-Site Dashboards • Backend SDKs • Synthetic Traps    ║
    ╚══════════════════════════════════════════════════════════════╝\033[0m
    """
    print(banner)


def init_database():
    """Initialize the multi-tenant database tables."""
    logger.info("Initializing database...")
    from database.db_setup import init_db
    init_db()
    logger.info("Database initialized successfully.")


def init_engine():
    """Initialize shared backend engine singletons."""
    logger.info("Initializing Backend Engine (Scoring, Quarantine, Alerts, Geo)...")
    from engine.geo_enricher import GeoEnricher
    from engine.quarantine import QuarantineManager
    from engine.scoring_engine import ScoringEngine
    GeoEnricher()
    QuarantineManager()
    ScoringEngine()
    logger.info("Backend Engine initialized successfully.")


def start_quarantine_checker():
    """Periodically check and expire quarantined IPs."""
    try:
        from engine.quarantine import QuarantineManager
        qm = QuarantineManager()
        logger.info("🛡️  Starting Quarantine Expiry Checker...")
        while True:
            qm.check_expired()
            time.sleep(60)
    except Exception as e:
        logger.error(f"Quarantine Checker failed: {e}")


def start_dashboard():
    """Start the MIRAGE Shield analytics dashboard & customer API."""
    try:
        from config.settings import DASHBOARD_PORT
        from dashboard.app import create_app
        logger.info(f"📊 Starting MIRAGE Shield Platform on port {DASHBOARD_PORT}...")
        app = create_app()
        app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Dashboard failed to start: {e}")


def start_mirage_shield():
    """Start the MIRAGE Shield deception reverse proxy."""
    try:
        from config.settings import SHIELD_PORT, SHIELD_TARGET_URL
        from mirage_shield.shield_proxy import get_shield_instance
        shield = get_shield_instance(target_url=SHIELD_TARGET_URL)
        shield.shield_port = SHIELD_PORT
        logger.info(f"🛡️  Starting MIRAGE Shield Proxy on port {SHIELD_PORT} (origin: {SHIELD_TARGET_URL})...")
        shield.run(port=SHIELD_PORT)
    except Exception as e:
        logger.error(f"MIRAGE Shield failed to start: {e}")


if __name__ == "__main__":
    print_banner()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    init_database()

    if "--clean" in sys.argv:
        try:
            from database.db_manager import DatabaseManager
            db_clean = DatabaseManager()
            conn = db_clean.get_connection()
            for tbl in ("events", "attackers", "site_attackers", "credentials", "quarantine_log", "honeytoken_triggers"):
                conn.execute(f"DELETE FROM {tbl}")
            conn.execute("UPDATE sites SET total_absorbed = 0, fake_records_served = 0, last_attack_at = NULL")
            conn.commit()
            conn.close()
            logger.info("🧹 Cleared all previous telemetry rows.")
        except Exception as e:
            logger.error(f"Failed cleaning database: {e}")

    init_engine()

    services = [
        ("Quarantine Checker", start_quarantine_checker),
        ("Dashboard Platform", start_dashboard),
    ]
    if "--no-shield" not in sys.argv:
        services.append(("MIRAGE Shield Proxy", start_mirage_shield))

    for name, target in services:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        time.sleep(0.4)

    print()
    logger.info("=" * 60)
    logger.info("🚀 MIRAGE Shield Platform is ONLINE!")
    logger.info("=" * 60)
    logger.info("📊 Platform Overview: http://localhost:5000")
    logger.info("🏢 Protected Sites:   http://localhost:5000/sites")
    logger.info("🛡️  Standalone Proxy:  http://localhost:8443/mirage-shield/dashboard")
    logger.info("=" * 60)
    logger.info("Press Ctrl+C to shut down.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.info("🛑 Shutting down MIRAGE Shield... Goodbye!")
        sys.exit(0)
