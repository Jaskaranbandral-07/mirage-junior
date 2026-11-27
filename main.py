"""
MIRAGE Shield — Main Entry Point
Multi-layered Intelligent Response & Adaptive Gathering Engine

Starts all honeypot services, MIRAGE Shield proxy, multi-tenant dashboards,
and active defense monitors.
Usage:
    python main.py           # Normal mode
    python main.py --demo    # Demo mode (seeds database with sample attack data)
"""

import threading
import time
import sys
import os
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('MIRAGE')


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
    """Initialize the database tables."""
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


def seed_demo_data():
    """Seed the database with realistic demo data."""
    logger.info("🎭 Running in DEMO MODE — Seeding database with fake attack data...")
    try:
        from dashboard.demo_data import seed_data
        seed_data()
        logger.info("✅ Demo data seeded successfully.")
    except Exception as e:
        logger.error(f"Failed to seed demo data: {e}")


def start_http_decoy():
    """Start the HTTP honeypot decoy server."""
    try:
        from honeypots.http_decoy import run_http_decoy
        logger.info("🌐 Starting HTTP Decoy on port 8080...")
        run_http_decoy()
    except Exception as e:
        logger.error(f"HTTP Decoy failed to start: {e}")


def start_ssh_trap():
    """Start the SSH honeypot trap."""
    try:
        from honeypots.ssh_trap import run_ssh_trap
        logger.info("🖥️  Starting SSH Trap on port 2222...")
        run_ssh_trap()
    except Exception as e:
        logger.error(f"SSH Trap failed to start: {e}")


def start_ftp_trap():
    """Start the FTP honeypot trap."""
    try:
        from honeypots.ftp_trap import run_ftp_trap
        logger.info("📁 Starting FTP Trap on port 2121...")
        run_ftp_trap()
    except Exception as e:
        logger.error(f"FTP Trap failed to start: {e}")


def start_honeytoken_monitor():
    """Start the honeytoken file system monitor."""
    try:
        from engine.honeytoken_monitor import HoneytokenMonitor
        logger.info("🪤 Starting Honeytoken File Monitor...")
        monitor = HoneytokenMonitor()
        monitor.start()
    except Exception as e:
        logger.error(f"Honeytoken Monitor failed to start: {e}")


def start_quarantine_checker():
    """Periodically check and expire quarantined IPs."""
    try:
        from engine.quarantine import QuarantineManager
        qm = QuarantineManager()
        logger.info("🛡️  Starting Quarantine Expiry Checker...")
        while True:
            qm.check_expired()
            time.sleep(60)  # Check every 60 seconds
    except Exception as e:
        logger.error(f"Quarantine Checker failed: {e}")


def start_dashboard():
    """Start the Flask analytics dashboard."""
    try:
        from dashboard.app import create_app
        logger.info("📊 Starting Dashboard on port 5000...")
        app = create_app()
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Dashboard failed to start: {e}")


def start_mirage_shield():
    """Start the MIRAGE Shield deception reverse proxy."""
    try:
        from config.settings import SHIELD_PORT, SHIELD_TARGET_URL
        from mirage_shield.shield_proxy import get_shield_instance
        # Wait briefly so HTTP Decoy (:8080) is online before pre-cloning
        time.sleep(1.5)
        shield = get_shield_instance(target_url=SHIELD_TARGET_URL)
        shield.shield_port = SHIELD_PORT
        logger.info(f"🛡️  Starting MIRAGE Shield on port {SHIELD_PORT} (protecting {SHIELD_TARGET_URL})...")
        shield.run(port=SHIELD_PORT)
    except Exception as e:
        logger.error(f"MIRAGE Shield failed to start: {e}")


if __name__ == "__main__":
    print_banner()

    # Change working directory to the project root
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Initialize database
    init_database()

    # Clear previous/demo data if --clean flag is passed
    if "--clean" in sys.argv:
        try:
            from database.db_manager import DatabaseManager
            db_clean = DatabaseManager()
            conn = db_clean.get_connection()
            for tbl in ("events", "attackers", "site_attackers", "credentials", "quarantine_log", "honeytoken_triggers"):
                conn.execute(f"DELETE FROM {tbl}")
            conn.commit()
            conn.close()
            logger.info("🧹 Cleared all previous telemetry rows for clean live capture.")
        except Exception as e:
            logger.error(f"Failed cleaning database: {e}")

    # Initialize shared engine singletons
    init_engine()

    # Seed demo data if --demo flag is passed
    if "--demo" in sys.argv:
        seed_demo_data()

    # Define all services as daemon threads
    services = [
        ("HTTP Decoy",          start_http_decoy),
        ("SSH Trap",            start_ssh_trap),
        ("FTP Trap",            start_ftp_trap),
        ("Honeytoken Monitor",  start_honeytoken_monitor),
        ("Quarantine Checker",  start_quarantine_checker),
        ("Dashboard",           start_dashboard),
    ]
    if "--no-shield" not in sys.argv:
        services.append(("MIRAGE Shield", start_mirage_shield))

    threads = []
    for name, target in services:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.5)  # Stagger startup slightly

    print()
    logger.info("=" * 60)
    logger.info("🚀 ALL SYSTEMS ONLINE — MIRAGE Shield is running!")
    logger.info("=" * 60)
    logger.info("📊 Dashboard:     http://localhost:5000")
    logger.info("🏢 Client Sites:  http://localhost:5000/sites")
    logger.info("🛡️  MIRAGE Shield: http://localhost:8443/mirage-shield/dashboard")
    logger.info("🌐 HTTP Decoy:    http://localhost:8080")
    logger.info("🖥️  SSH Trap:      ssh localhost -p 2222")
    logger.info("📁 FTP Trap:      ftp localhost 2121")
    logger.info("=" * 60)
    logger.info("Press Ctrl+C to shut down all services.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.info("🛑 Shutting down MIRAGE Shield... Goodbye!")
        sys.exit(0)
