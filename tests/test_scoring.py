import pytest
import sqlite3
import os
import sys
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_setup import init_db
import database.db_manager as db_m
import database.db_setup as db_s
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine
from engine.quarantine import QuarantineManager
from config import settings


@pytest.fixture
def setup_env(tmp_path):
    """Create a temporary database and scoring engine for testing."""
    db_path = str(tmp_path / 'test_mirage.db')
    # Override settings and module-level paths for isolation
    original_settings_db = settings.DATABASE_PATH
    original_db_m_path = db_m.DATABASE_PATH
    original_db_s_path = db_s.DATABASE_PATH

    settings.DATABASE_PATH = db_path
    db_m.DATABASE_PATH = db_path
    db_s.DATABASE_PATH = db_path

    # Reset singleton instances to ensure fresh instance using temp DB
    ScoringEngine._instance = None
    QuarantineManager._instance = None

    # Initialize DB using project schema
    init_db()

    db = DatabaseManager()
    engine = ScoringEngine()
    engine.db = db

    yield db, engine, db_path

    # Restore original paths and reset singletons
    ScoringEngine._instance = None
    QuarantineManager._instance = None
    settings.DATABASE_PATH = original_settings_db
    db_m.DATABASE_PATH = original_db_m_path
    db_s.DATABASE_PATH = original_db_s_path


def _extract_score(res):
    """Helper to handle either a raw numeric score or a (score, classification) tuple."""
    if isinstance(res, (tuple, list)):
        return res[0]
    return res


def test_score_starts_at_zero(setup_env):
    db, engine, _ = setup_env
    res = engine.calculate_threat_score('10.0.0.99')
    score = _extract_score(res)
    assert score == 0


def test_score_increases_with_events(setup_env):
    db, engine, _ = setup_env
    ip = '192.0.2.1'
    db.log_event(ip, 8080, 'HTTP', 'connection', '', 5, None)
    res = engine.calculate_threat_score(ip)
    score = _extract_score(res)
    assert score > 0


def test_score_caps_at_100(setup_env):
    db, engine, _ = setup_env
    ip = '192.0.2.2'
    # Log many high-value events to exceed 100
    for _ in range(10):
        db.log_event(ip, 8080, 'HTTP', 'honeytoken_trigger', '', 25, 'T1083')
    res = engine.calculate_threat_score(ip)
    score = _extract_score(res)
    assert score <= 100


def test_classification_scanner(setup_env):
    db, engine, _ = setup_env
    ip = '192.0.2.3'
    db.log_event(ip, 8080, 'HTTP', 'connection', '', 5, None)
    res = engine.calculate_threat_score(ip)
    if isinstance(res, (tuple, list)):
        assert res[1] == 'SCANNER'
    # Read back from DB
    profile = db.get_attacker_profile(ip)
    assert profile is not None
    assert profile['classification'] == 'SCANNER'


def test_classification_critical(setup_env):
    db, engine, _ = setup_env
    ip = '192.0.2.4'
    for _ in range(5):
        db.log_event(ip, 8080, 'HTTP', 'honeytoken_trigger', '', 25, 'T1083')
        db.log_event(ip, 2222, 'SSH', 'shell_access', '', 15, 'T1033')
    res = engine.calculate_threat_score(ip)
    if isinstance(res, (tuple, list)):
        assert res[1] == 'CRITICAL'
    profile = db.get_attacker_profile(ip)
    assert profile is not None
    assert profile['classification'] == 'CRITICAL'


def test_lateral_scan_bonus(setup_env):
    db, engine, _ = setup_env
    ip = '192.0.2.5'
    db.log_event(ip, 8080, 'HTTP', 'connection', '', 5, None)
    db.log_event(ip, 2222, 'SSH', 'connection', '', 5, None)
    res = engine.calculate_threat_score(ip)
    score = _extract_score(res)
    # Should include lateral_scan bonus (15 pts) plus 2 connections (5+5)
    assert score >= 25
