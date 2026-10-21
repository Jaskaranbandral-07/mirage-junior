"""
Vercel Deployment Entry Point for MIRAGE Junior Dashboard
Since Vercel is a serverless HTTP platform, this file launches the 
Flask Analytics Dashboard (with demo telemetry) for the prototype showcase.
The SSH, HTTP honeypot ports, and FTP traps run on dedicated hosts/ports.
"""
import os
import sys

# Ensure the app can find its modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("VERCEL", "1")

# Seed the database for the Vercel prototype if it's empty
try:
    import config.settings as settings_cfg
    from database.db_setup import init_db
    from dashboard.demo_data import seed_data
    import sqlite3
    
    # Initialize the database (automatically uses /tmp on Vercel)
    init_db()
    
    db_path = settings_cfg.DATABASE_PATH
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    
    if count == 0:
        seed_data()
except Exception as e:
    print(f"Error initializing demo database for Vercel: {e}")

# Import and expose the Flask app for Vercel's WSGI server
from dashboard.app import create_app
app = create_app()

