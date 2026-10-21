"""
MIRAGE Junior — Main Entry Point
Multi-layered Intelligent Response & Adaptive Gathering Engine (Junior Edition)

Starts all honeypot services, the dashboard, and monitoring systems.
Usage:
    python main.py           # Normal mode
    python main.py --demo    # Demo mode (seeds database with fake attack data)
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
    """Print the MIRAGE Junior ASCII art banner."""
    banner = """
    \033[92m
    ███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗         ██╗██████╗ 
    ████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝         ██║██╔══██╗
    ██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗           ██║██████╔╝
    ██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝      ██  ██║██╔══██╗
    ██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗    ╚█████╔╝██║  ██║
    ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝     ╚════╝ ╚═╝  ╚═╝
    \033[0m
    \033[96m╔══════════════════════════════════════════════════════════════╗
    ║   Multi-layered Intelligent Response & Adaptive Gathering   ║
    ║                    Engine — Junior Edition                   ║
    ║           Next-Gen Intelligent Deception Network             ║
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


if __name__ == "__main__":
    print_banner()

    # Change working directory to the project root
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Initialize database
    init_database()

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

    threads = []
    for name, target in services:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.5)  # Stagger startup slightly

    print()
    logger.info("=" * 60)
    logger.info("🚀 ALL SYSTEMS ONLINE — MIRAGE Junior is running!")
    logger.info("=" * 60)
    logger.info("📊 Dashboard:   http://localhost:5000")
    logger.info("🌐 HTTP Decoy:  http://localhost:8080")
    logger.info("🖥️  SSH Trap:    ssh localhost -p 2222")
    logger.info("📁 FTP Trap:    ftp localhost 2121")
    logger.info("=" * 60)
    logger.info("Press Ctrl+C to shut down all services.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.info("🛑 Shutting down MIRAGE Junior... Goodbye!")
        sys.exit(0)
