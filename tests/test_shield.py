"""
Tests for MIRAGE Shield — Deception-as-a-Service Middleware
Covers TrafficAnalyzer, SiteCloner, HoneypotInjector, ShieldProxy routing,
and main Dashboard /shield integration.
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
import database.db_manager as db_m
import database.db_setup as db_s
from database.db_setup import init_db
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine
from engine.quarantine import QuarantineManager
from mirage_shield.traffic_analyzer import TrafficAnalyzer, ALLOW, REDIRECT, BLOCK
from mirage_shield.honeypot_injector import HoneypotInjector
from mirage_shield.site_cloner import SiteCloner
from mirage_shield.shield_proxy import ShieldProxy, reset_shield_instance


@pytest.fixture
def isolated_shield(tmp_path):
    """Create an isolated DB and ShieldProxy instance for unit tests."""
    db_path = str(tmp_path / "test_shield.db")
    orig_settings_db = settings.DATABASE_PATH
    orig_db_m = db_m.DATABASE_PATH
    orig_db_s = db_s.DATABASE_PATH

    settings.DATABASE_PATH = db_path
    db_m.DATABASE_PATH = db_path
    db_s.DATABASE_PATH = db_path

    ScoringEngine._instance = None
    QuarantineManager._instance = None
    reset_shield_instance()

    init_db()
    db = DatabaseManager()
    qm = QuarantineManager()
    se = ScoringEngine()

    shield = ShieldProxy(
        target_url="http://127.0.0.1:8080",
        db_manager=db,
        scoring_engine=se,
        quarantine_manager=qm,
        auto_init_backend=False,
    )
    shield.cloner = SiteCloner("http://127.0.0.1:8080", clone_dir=str(tmp_path / "clones"))
    shield.cloner._create_fallback_clone()

    yield shield, db

    ScoringEngine._instance = None
    QuarantineManager._instance = None
    reset_shield_instance()
    settings.DATABASE_PATH = orig_settings_db
    db_m.DATABASE_PATH = orig_db_m
    db_s.DATABASE_PATH = orig_db_s


def test_analyzer_allows_normal_browser():
    analyzer = TrafficAnalyzer(inspect_localhost=True)
    decision, score, _ = analyzer.analyze(
        ip="203.0.113.10",
        path="/products",
        method="GET",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
        headers={"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip"},
    )
    assert decision == ALLOW
    assert score < 40


def test_analyzer_redirects_env_probe():
    analyzer = TrafficAnalyzer(inspect_localhost=True)
    decision, score, breakdown = analyzer.analyze(
        ip="203.0.113.20",
        path="/.env",
        method="GET",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) Chrome/122.0.0.0 Safari/537.36",
        headers={"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip"},
    )
    assert decision == REDIRECT
    assert score >= 40
    assert breakdown["suspicious_path"] >= 40


def test_analyzer_blocks_sqlmap_attack():
    analyzer = TrafficAnalyzer(inspect_localhost=True)
    decision, score, breakdown = analyzer.analyze(
        ip="198.51.100.55",
        path="/login",
        method="POST",
        user_agent="sqlmap/1.7.11",
        headers={},
        query_string="id=1' OR '1'='1'--",
    )
    assert decision == BLOCK
    assert score >= 80
    assert "sql_injection" in breakdown["attack_types"]


def test_sticky_honeypot_session():
    """Once diverted to the honeypot clone, attacker stays in the clone on /."""
    analyzer = TrafficAnalyzer(inspect_localhost=True)
    d1, _, _ = analyzer.analyze(
        ip="198.51.100.77",
        path="/admin",
        method="GET",
        user_agent="Mozilla/5.0 Chrome/122.0.0.0",
        headers={"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip"},
    )
    assert d1 == REDIRECT

    d2, score2, _ = analyzer.analyze(
        ip="198.51.100.77",
        path="/",
        method="GET",
        user_agent="Mozilla/5.0 Chrome/122.0.0.0",
        headers={"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip"},
    )
    assert d2 == REDIRECT
    assert score2 >= 40


def test_injector_serves_traps_and_captures_credentials(isolated_shield):
    shield, db = isolated_shield
    client = shield.app.test_client()

    # Probe /.env via fake attacker IP header
    resp_env = client.get("/.env", headers={
        "X-MIRAGE-Client-IP": "45.155.205.99",
        "User-Agent": "Mozilla/5.0 Chrome/122.0.0.0",
        "Accept": "text/html",
        "Accept-Language": "en-US",
        "Accept-Encoding": "gzip",
    })
    assert resp_env.status_code == 200
    assert b"AWS_ACCESS_KEY_ID" in resp_env.data

    # Submit fake credentials inside trapped /admin
    resp_login = client.post("/admin/login", data={
        "username": "admin_evil",
        "password": "P@ssword123",
    }, headers={
        "X-MIRAGE-Client-IP": "45.155.205.99",
        "User-Agent": "Mozilla/5.0 Chrome/122.0.0.0",
        "Accept": "text/html",
    })
    assert resp_login.status_code in (200, 401, 403)
    creds = shield.injector.get_captured_credentials()
    assert any(c["username"] == "admin_evil" and c["password"] == "P@ssword123" for c in creds)


def test_shield_dashboard_and_simulation_routes(isolated_shield):
    shield, _ = isolated_shield
    client = shield.app.test_client()

    dash = client.get("/mirage-shield/dashboard")
    assert dash.status_code == 200
    assert b"MIRAGE" in dash.data

    sim = client.post("/mirage-shield/api/simulate", json={"scenario": "sqli"})
    assert sim.status_code == 200
    payload = sim.get_json()
    assert payload["decision"] == BLOCK
    assert payload["score"] >= 80

    beacon = client.post("/mirage-shield/api/beacon", json={"ip": "45.155.205.99", "page": "/"})
    assert beacon.status_code == 200

    unblock = client.post("/mirage-shield/api/unblock/194.26.29.112")
    assert unblock.status_code == 200
    assert unblock.get_json()["success"] is True


def test_cloner_fallback_and_deception_injection(tmp_path):
    cloner = SiteCloner("http://127.0.0.1:59999", clone_dir=str(tmp_path))
    clone_path = cloner._create_fallback_clone()
    assert os.path.exists(os.path.join(clone_path, "index.html"))

    injector = HoneypotInjector()
    with open(os.path.join(clone_path, "index.html"), "r", encoding="utf-8") as f:
        raw_html = f.read()
    injected = injector.inject_deception_layer(raw_html, "10.20.30.40")
    assert "/mirage-shield/api/beacon" in injected
    assert "/.env" in injected


def test_main_dashboard_shield_integration(isolated_shield):
    """Verify /shield and /api/shield/* work inside the main MIRAGE Junior Flask app."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield

    app = create_app()
    client = app.test_client()

    page = client.get("/shield")
    assert page.status_code == 200
    assert b"MIRAGE Shield" in page.data

    sim = client.post("/api/shield/simulate", json={"scenario": "recon_env"})
    assert sim.status_code == 200
    assert sim.get_json()["decision"] == REDIRECT

    stats = client.get("/api/shield/stats")
    assert stats.status_code == 200
    assert stats.get_json()["redirected"] >= 1
    assert stats.headers.get("Access-Control-Allow-Origin") == "*"

    preflight = client.options("/api/shield/clone")
    assert preflight.status_code == 204
    assert preflight.headers.get("Access-Control-Allow-Origin") == "*"

    shield_client = shield.app.test_client()
    proxy_preflight = shield_client.options("/mirage-shield/api/clone")
    assert proxy_preflight.status_code == 204
    assert proxy_preflight.headers.get("Access-Control-Allow-Origin") == "*"


def test_real_web_trap_capture_and_purge(isolated_shield):
    """Verify real HTTP probes on the dashboard app capture real IPs, creds, and purge cleanly."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, db = isolated_shield
    shield_proxy._shared_shield_instance = shield

    app = create_app()
    client = app.test_client()

    # Ensure clean start via /api/clear-data
    clear_res = client.post("/api/clear-data")
    assert clear_res.status_code == 200
    assert clear_res.get_json()["status"] == "success"

    # Real external IP probe via X-Forwarded-For on /.env
    env_res = client.get("/.env", headers={
        "X-Forwarded-For": "198.51.100.88",
        "User-Agent": "curl/8.4.0",
    })
    assert env_res.status_code == 200
    assert b"AWS_ACCESS_KEY_ID" in env_res.data

    # Real credential capture on /wp-login.php
    wp_res = client.post("/wp-login.php", data={
        "log": "real_attacker",
        "pwd": "RealCapturedPassword!99",
    }, headers={
        "X-Forwarded-For": "198.51.100.88",
        "User-Agent": "Mozilla/5.0 Chrome/122.0.0.0",
    })
    assert wp_res.status_code in (200, 401, 403)

    events = db.get_events_by_ip("198.51.100.88")
    assert len(events) >= 1

    # Verify purge removes all captured telemetry cleanly
    purge = client.post("/api/clear-data")
    assert purge.status_code == 200
    assert db.get_stats()["total_hits"] == 0


def test_site_cloner_preserves_assets_and_traps_forms(tmp_path):
    """Verify SiteCloner resolves CSS/img/srcset cleanly while trapping forms & internal links."""
    from unittest.mock import patch, MagicMock
    sample_html = """
    <html>
      <head>
        <link rel="stylesheet" href="/assets/main.css">
        <style>.hero { background-image: url('/images/hero.png'); }</style>
      </head>
      <body>
        <img src="/logo.svg" srcset="/logo-1x.png 1x, /logo-2x.png 2x">
        <a href="/tutorials/python">Python</a>
        <form action="https://www.example.com/auth/login" method="POST">
          <input name="username"><input name="password">
        </form>
      </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.text = sample_html
    mock_resp.url = "https://www.example.com/"
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_resp.raise_for_status = MagicMock()

    cloner = SiteCloner("https://www.example.com", clone_dir=str(tmp_path))
    with patch.object(cloner.session, "get", return_value=mock_resp):
        cloner.clone(max_pages=1)

    with open(cloner.get_index_path(), "r", encoding="utf-8") as f:
        cloned = f.read()

    assert "https://www.example.com/assets/main.css" in cloned
    assert "https://www.example.com/images/hero.png" in cloned
    assert "https://www.example.com/logo.svg" in cloned
    assert "https://www.example.com/logo-2x.png 2x" in cloned
    # Internal links and forms remain relative so traffic stays inside MIRAGE Shield
    assert 'href="/tutorials/python"' in cloned
    assert 'action="/auth/login"' in cloned




