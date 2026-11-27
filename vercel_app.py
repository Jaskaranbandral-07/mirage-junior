"""
Vercel Deployment Entry Point for MIRAGE Shield
Runs multi-tenant per-website dashboards, backend SDK ingestion,
synthetic fake-data deception, GeoIP enrichment, and MITRE ATT&CK tagging
without any pre-seeded fake data.
"""
import os
import sys

# Ensure the app can find its modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("VERCEL", "1")

# Initialize clean empty SQLite schema (uses /tmp on Vercel)
try:
    from database.db_setup import init_db
    init_db()
except Exception as e:
    print(f"Error initializing database: {e}")

# Expose the Flask app for Vercel's WSGI server
from dashboard.app import create_app
app = create_app()
