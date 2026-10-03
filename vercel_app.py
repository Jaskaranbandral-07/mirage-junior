"""
Vercel Deployment Entry Point for MIRAGE Junior Dashboard
Since Vercel is a serverless HTTP platform, this file only launches the 
Flask Analytics Dashboard (in demo mode) for the prototype showcase.
The SSH and FTP traps require a dedicated server and run locally.
"""
import os
import sys

# Ensure the app can find its modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Seed the database for the Vercel prototype if it's empty
try:
    from database.db_setup import init_db
    from dashboard.demo_data import seed_data
    import sqlite3
    
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'mirage_junior.db')
    init_db()
    
    # Check if we need to seed
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    
    if count == 0:
        seed_data()
except Exception as e:
    print(f"Error initializing demo database: {e}")

# Import and expose the Flask app for Vercel's WSGI server
from dashboard.app import create_app
app = create_app()
