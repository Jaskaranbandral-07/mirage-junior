import pytest
import sqlite3
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
import database.db_manager as db_m
import database.db_setup as db_s
from database.db_setup import init_db
from database.db_manager import DatabaseManager
from engine.honeytoken_monitor import HoneytokenMonitor, HoneytokenHandler


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary isolated database for honeytoken tests."""
    db_path = str(tmp_path / 'test_honeytokens.db')
    original_settings_db = settings.DATABASE_PATH
    original_db_m_path = db_m.DATABASE_PATH
    original_db_s_path = db_s.DATABASE_PATH

    settings.DATABASE_PATH = db_path
    db_m.DATABASE_PATH = db_path
    db_s.DATABASE_PATH = db_path

    try:
        from engine.scoring_engine import ScoringEngine
        ScoringEngine._instance = None
    except ImportError:
        pass
    try:
        from engine.quarantine import QuarantineManager
        QuarantineManager._instance = None
    except ImportError:
        pass

    init_db()
    db = DatabaseManager()

    yield db, db_path

    try:
        from engine.scoring_engine import ScoringEngine
        ScoringEngine._instance = None
    except ImportError:
        pass
    try:
        from engine.quarantine import QuarantineManager
        QuarantineManager._instance = None
    except ImportError:
        pass

    settings.DATABASE_PATH = original_settings_db
    db_m.DATABASE_PATH = original_db_m_path
    db_s.DATABASE_PATH = original_db_s_path


def test_honeytoken_monitor_instantiation():
    """Test that HoneytokenMonitor can be instantiated and initialized properly."""
    monitor = HoneytokenMonitor()
    assert monitor is not None
    assert monitor.daemon is True
    assert monitor.bait_dir is not None
    assert os.path.exists(monitor.bait_dir)
    assert monitor.observer is not None
    assert isinstance(monitor.handler, HoneytokenHandler)


def test_bait_directory_exists_and_contains_files():
    """Test that the bait directory exists and contains expected honeytoken files."""
    bait_dir = os.path.abspath(settings.BAIT_DIRECTORY)
    assert os.path.exists(bait_dir), f"Bait directory not found at {bait_dir}"
    assert os.path.isdir(bait_dir), f"Bait path {bait_dir} is not a directory"

    files = os.listdir(bait_dir)
    expected_files = ['admin_passwords.txt', 'backup_database.sql']
    for expected in expected_files:
        assert expected in files, f"Expected bait file {expected} not found in {bait_dir}"
        file_path = os.path.join(bait_dir, expected)
        assert os.path.getsize(file_path) > 0, f"Bait file {expected} is empty"


def test_log_honeytoken_trigger_insertion(temp_db):
    """Test that DatabaseManager.log_honeytoken_trigger correctly inserts records."""
    db, _ = temp_db
    token_name = "admin_passwords.txt"
    token_type = "filesystem"
    ip_address = "192.0.2.42"
    process_name = "notepad.exe"
    details = "File modified"

    db.log_honeytoken_trigger(
        token_name=token_name,
        token_type=token_type,
        ip_address=ip_address,
        process_name=process_name,
        details=details
    )

    conn = db.get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeytoken_triggers WHERE token_name = ?", (token_name,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row["token_name"] == token_name
    assert row["token_type"] == token_type
    assert row["ip_address"] == ip_address
    assert row["process_name"] == process_name
    assert row["details"] == details
    assert row["timestamp"] is not None


def test_honeytoken_handler_trigger(temp_db):
    """Test that HoneytokenHandler logs an event via DatabaseManager."""
    db, _ = temp_db
    handler = HoneytokenHandler()

    class FakeFileEvent:
        is_directory = False
        src_path = os.path.join(settings.BAIT_DIRECTORY, "backup_database.sql")

    fake_event = FakeFileEvent()
    handler.on_modified(fake_event)

    conn = db.get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeytoken_triggers WHERE token_name = ?", ("backup_database.sql",))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row["token_name"] == "backup_database.sql"
    assert row["token_type"] == "filesystem"
    assert row["ip_address"] == "localhost"
    assert row["details"] == "File modified"
