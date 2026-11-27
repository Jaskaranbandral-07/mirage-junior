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
    """Verify platform root stays clean (no self-traps) while customer portals capture traps & purge cleanly."""
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

    # MIRAGE Shield platform root should NOT trap itself
    root_probe = client.get("/.env")
    assert root_probe.status_code == 404

    # Customer portal trap probe via X-Forwarded-For on /portal/demo-target.com/.env
    env_res = client.get("/portal/demo-target.com/.env", headers={
        "X-Forwarded-For": "198.51.100.88",
        "User-Agent": "curl/8.4.0",
    })
    assert env_res.status_code == 200
    assert b"AWS_ACCESS_KEY_ID" in env_res.data

    # Real credential capture inside cloned customer portal
    wp_res = client.post("/portal/demo-target.com/wp-login.php", data={
        "log": "real_attacker",
        "pwd": "RealCapturedPassword!99",
    }, headers={
        "X-Forwarded-For": "198.51.100.88",
        "User-Agent": "Mozilla/5.0 Chrome/122.0.0.0",
    })
    assert wp_res.status_code in (200, 401, 403)

    events = db.get_events_by_ip("198.51.100.88")
    assert len(events) >= 1
    assert all(e["site_id"] == "demo-target-com" for e in events)

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

    # Portal prefixing keeps links/forms inside /portal/<domain> without touching external asset URLs
    prefixed = cloner.apply_portal_prefix(cloned, "/portal/www.example.com")
    assert 'href="/portal/www.example.com/tutorials/python"' in prefixed
    assert 'action="/portal/www.example.com/auth/login"' in prefixed
    assert 'https://www.example.com/assets/main.css' in prefixed


def test_portal_subpage_routing_no_404(isolated_shield, tmp_path):
    """Clicking any cloned subpage or via Referer inside /portal/<domain> never 404s."""
    from unittest.mock import patch, MagicMock
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    shield.cloner = SiteCloner("https://www.example.com", clone_dir=str(tmp_path / "portal_clones"))

    subpage_html = "<html><body><h1>Python Programming</h1><a href='/loops'>Loops</a></body></html>"
    mock_resp = MagicMock()
    mock_resp.text = subpage_html
    mock_resp.url = "https://www.example.com/python-programming"
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.raise_for_status = MagicMock()

    app = create_app()
    client = app.test_client()

    with patch.object(shield.cloner.session, "get", return_value=mock_resp):
        res = client.get("/portal/www.example.com/python-programming")
        assert res.status_code == 200
        assert b"Python Programming" in res.data
        assert b"/portal/www.example.com/loops" in res.data

        # Simulate JS-driven navigation to /loops with Referer from /portal/www.example.com
        res_ref = client.get("/loops", headers={
            "Referer": "https://mirage-junior.vercel.app/portal/www.example.com/python-programming"
        })
        assert res_ref.status_code == 200
        assert b"Python Programming" in res_ref.data


def test_multi_tenant_site_isolation_and_fake_data(isolated_shield):
    """Two customer websites stay isolated and absorb attacks with useless fake data."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, db = isolated_shield
    shield_proxy._shared_shield_instance = shield
    app = create_app()
    client = app.test_client()

    r1 = client.post("/api/sites/register", json={"target_url": "https://alpha-shop.com", "owner_name": "Alpha"})
    r2 = client.post("/api/sites/register", json={"target_url": "https://beta-fintech.io", "owner_name": "Beta"})
    assert r1.status_code == 200 and r2.status_code == 200
    s1 = r1.get_json()
    s2 = r2.get_json()
    assert s1["site_id"] != s2["site_id"]
    assert s1["api_key"] != s2["api_key"]

    # Absorb SQLi probe strictly on alpha-shop.com
    absorb = client.post(f"/api/site/{s1['site_id']}/test-absorb", json={"kind": "sqli"}, headers={
        "X-MIRAGE-Client-IP": "198.51.100.44",
    })
    assert absorb.status_code == 200
    adata = absorb.get_json()
    assert adata["fake_records_served"] >= 1
    assert "DECOY" in adata["fake_response_preview"]

    # Verify alpha has the event while beta stays at 0
    stats1 = client.get(f"/api/site/{s1['site_id']}/stats").get_json()
    stats2 = client.get(f"/api/site/{s2['site_id']}/stats").get_json()
    assert stats1["total_hits"] >= 1
    assert stats2["total_hits"] == 0

    # Customer private share key check
    bad_dash = client.get(f"/site/{s1['site_id']}?key=wrong_token")
    assert bad_dash.status_code == 403
    good_dash = client.get(s1["share_url"].replace("http://localhost", ""))
    assert good_dash.status_code == 200
    assert b"alpha-shop.com" in good_dash.data


def test_python_backend_sdk_absorbs_attacks_and_ingests(isolated_shield):
    """Customer Flask backend wrapped with protect_flask_app absorbs SQLi before DB route runs."""
    from flask import Flask, jsonify
    from dashboard.app import create_app
    from mirage_shield import shield_proxy
    from mirage_shield.sdk.python_shield import protect_flask_app

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    mirage_app = create_app()
    mirage_client = mirage_app.test_client()

    reg = mirage_client.post("/api/sites/register", json={"target_url": "https://customer-api.dev"}).get_json()
    site_key = reg["api_key"]
    site_id = reg["site_id"]

    # Simulated customer startup backend
    customer_app = Flask("customer_backend")
    backend_hit_counter = {"count": 0}

    @customer_app.route("/api/users")
    def real_users():
        backend_hit_counter["count"] += 1
        return jsonify({"real_secret_users": ["real_ceo@customer-api.dev"]})

    protect_flask_app(customer_app, site_key=site_key, shield_url="", domain="customer-api.dev")
    cust_client = customer_app.test_client()

    # 1. Clean traffic passes to real customer backend
    clean_res = cust_client.get("/api/users", headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert clean_res.status_code == 200
    assert b"real_ceo@customer-api.dev" in clean_res.data
    assert backend_hit_counter["count"] == 1

    # 2. SQLi attack is absorbed by Shield — real backend NEVER executes, fake data returned!
    atk_res = cust_client.get("/api/users?id=1' OR '1'='1--", headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert atk_res.status_code == 200
    assert b"real_ceo@customer-api.dev" not in atk_res.data
    assert b"DECOY" in atk_res.data
    assert backend_hit_counter["count"] == 1

    # 3. Ingestion endpoint stores telemetry under the customer's site_id
    ing = mirage_client.post("/api/ingest", json={
        "ip": "203.0.113.77",
        "path": "/api/users",
        "method": "GET",
        "score": 50,
        "decision": "REDIRECT",
        "attack_types": ["sql_injection"],
        "fake_records_served": 5,
    }, headers={"X-MIRAGE-Site-Key": site_key})
    assert ing.status_code == 200
    assert ing.get_json()["site_id"] == site_id

    sdata = mirage_client.get(f"/api/site/{site_id}/stats").get_json()
    assert sdata["total_hits"] == 1
    assert sdata["site"]["fake_records_served"] == 5

    # Repeat ingest from same IP should NOT create duplicate active quarantine rows
    mirage_client.post("/api/ingest", json={
        "ip": "203.0.113.77",
        "path": "/.env",
        "method": "GET",
        "score": 85,
        "decision": "BLOCK",
        "attack_types": ["targeted_recon"],
        "fake_records_served": 1,
    }, headers={"X-MIRAGE-Site-Key": site_key})
    sdata2 = mirage_client.get(f"/api/site/{site_id}/stats").get_json()
    assert sdata2["ips_quarantined"] == 1


def test_extension_page_and_zip_download(isolated_shield):
    """Verify /extension page and 1-click /api/extension/download valid zip archive."""
    import io
    import zipfile
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    page = client.get("/extension")
    assert page.status_code == 200
    assert b"/api/extension/download" in page.data

    dl = client.get("/api/extension/download")
    assert dl.status_code == 200
    assert "application/zip" in (dl.headers.get("Content-Type") or "")
    assert "mirage-shield-extension.zip" in (dl.headers.get("Content-Disposition") or "")

    with zipfile.ZipFile(io.BytesIO(dl.data), "r") as zf:
        names = set(zf.namelist())
        assert "mirage-shield-extension/manifest.json" in names
        assert "mirage-shield-extension/popup.html" in names
        assert "mirage-shield-extension/popup.js" in names
        assert "mirage-shield-extension/icons/icon48.png" in names


def test_novapay_demo_target_standalone_functionality(isolated_shield):
    """Verify NovaPay demo site runs cleanly with zero MIRAGE references and working interactive endpoints."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy
    from demo_target.app import create_demo_app

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    mirage_client = create_app().test_client()
    assert mirage_client.get("/.env").status_code == 404

    demo_app = create_demo_app()
    demo_client = demo_app.test_client()

    home = demo_client.get("/")
    assert home.status_code == 200
    assert b"NovaPay" in home.data
    assert b"mirage" not in home.data.lower()

    # Merchant search & tier filtering
    cust = demo_client.get("/api/customers?tier=Enterprise").get_json()
    assert cust["status"] == "ok" and cust["count"] >= 2

    # Pricing & FX calculator
    quote = demo_client.post("/api/pricing/estimate", json={"volume_usd": 50000, "employees": 20, "currency": "INR"}).get_json()
    assert quote["status"] == "ok" and quote["currency"] == "INR" and quote["net_payout_local"] > 0

    # Invoice link generator
    inv = demo_client.post("/api/invoices", json={"client": "Zenith Labs", "amount": 1500, "currency": "USD"}).get_json()
    assert inv["status"] == "ok" and inv["invoice"]["invoice_id"].startswith("INV-")

    # Merchant portal login (clean auth check)
    bad_login = demo_client.post("/login", json={"email": "user@test.com", "password": "wrong"})
    assert bad_login.status_code == 401
    ok_login = demo_client.post("/login", json={"email": "demo@novapay.io", "password": "NovaPay@2026"})
    assert ok_login.status_code == 200 and ok_login.get_json()["status"] == "ok"

    # Silent backend WAF intercepts hostile probes with zero visible MIRAGE branding
    sqli_api = demo_client.get("/api/customers?q=1%27%20OR%20%271%27%3D%271--", headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert sqli_api.status_code == 200
    assert "X-Protected-By" not in sqli_api.headers
    assert b"DECOY" in sqli_api.data and b"CloudScale" not in sqli_api.data
    assert b"mirage" not in sqli_api.data.lower()

    env_trap = demo_client.get("/.env", headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert env_trap.status_code == 200 and b"DECOY" in env_trap.data

    trav = demo_client.get("/download?file=../../../../etc/passwd", headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert trav.status_code == 200 and b"root:x:0:0" in trav.data

    sqli_login = demo_client.post("/login", json={"email": "admin' OR '1'='1--", "password": "pw"}, headers={"User-Agent": "Mozilla/5.0 Chrome/122.0.0.0"})
    assert sqli_login.status_code == 200 and b"DECOY" in sqli_login.data


def test_sdk_download_endpoints_python_and_node(isolated_shield):
    """Verify per-site 1-click SDK downloads (/api/sdk/download/python & /node)."""
    import io
    import zipfile
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    reg = client.post("/api/sites/register", json={"target_url": "https://startup-app.io"}).get_json()
    sid = reg["site_id"]
    skey = reg["api_key"]

    site_page = client.get(f"/site/{sid}")
    assert site_page.status_code == 200
    assert b"/api/sdk/download/python" in site_page.data
    assert b"/api/sdk/download/node" in site_page.data

    py_dl = client.get(f"/api/sdk/download/python?site_id={sid}")
    assert py_dl.status_code == 200 and "application/zip" in (py_dl.headers.get("Content-Type") or "")
    with zipfile.ZipFile(io.BytesIO(py_dl.data), "r") as zf:
        names = set(zf.namelist())
        assert "mirage_shield/sdk/python_shield.py" in names
        assert "mirage_shield/synthetic_deception.py" in names
        assert "QUICKSTART.md" in names
        qs = zf.read("QUICKSTART.md").decode("utf-8")
        assert skey in qs and "startup-app.io" in qs

    node_dl = client.get(f"/api/sdk/download/node?site_id={sid}")
    assert node_dl.status_code == 200 and b"mirageShieldMiddleware" in node_dl.data


def test_cross_container_site_recovery_and_restore(isolated_shield):
    """Verify /site/<id>?target=... auto-recovers and /api/sites/restore preserves keys."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, db = isolated_shield
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    # 1. Simulate landing directly on /site/<id>?target=... on a cold container
    dash = client.get("/site/cloud-vendor-io?target=https://cloud-vendor.io")
    assert dash.status_code == 200
    assert b"cloud-vendor.io" in dash.data

    # 2. Simulate restoring saved browser sites into an empty container DB while keeping exact keys
    restore = client.post("/api/sites/restore", json={
        "sites": [{
            "target_url": "https://restored-client.dev",
            "owner_name": "Restored Co",
            "api_key": "ms_live_00112233445566778899aabbccddeeff",
            "dashboard_key": "dash_00112233445566778899aabb",
        }]
    })
    assert restore.status_code == 200
    rdata = restore.get_json()
    assert rdata["success"] is True and rdata["restored"] == 1
    saved = db.get_site("restored-client-dev")
    assert saved is not None
    assert saved["api_key"] == "ms_live_00112233445566778899aabbccddeeff"
    assert saved["dashboard_key"] == "dash_00112233445566778899aabb"


def test_root_is_sites_hub_and_single_probe_quarantines_and_traps_creds(isolated_shield):
    """Verify Overview is removed (root serves Protected Sites), SQLi/Cred probes hit >=25pts & quarantine, and inspector modal loads."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    # 1. Root '/' directly serves Protected Websites hub without Overview nav
    home = client.get("/")
    assert home.status_code == 200
    assert b"Protected Websites" in home.data
    assert b"Overview" not in home.data
    assert b"attack_inspector.js" in home.data

    reg = client.post("/api/sites/register", json={"target_url": "https://sec-check.dev"}).get_json()
    sid = reg["site_id"]

    # 2. Single SQLi probe triggers >=25 threat score and quarantines attacker IP
    sqli = client.post(f"/api/site/{sid}/test-absorb", json={"kind": "sqli"}, headers={"X-MIRAGE-Client-IP": "198.51.100.145"})
    assert sqli.status_code == 200

    # 3. Single Cred Login Trap captures trapped username/password AND hits threshold
    cred = client.post(f"/api/site/{sid}/test-absorb", json={"kind": "cred_trap"}, headers={"X-MIRAGE-Client-IP": "198.51.100.146"})
    assert cred.status_code == 200

    stats = client.get(f"/api/site/{sid}/stats").get_json()
    assert stats["ips_quarantined"] >= 2
    assert stats["creds_captured"] >= 1
    assert any(c["username"] == "admin' OR '1'='1--" for c in stats["credentials"])

    qpage = client.get("/quarantine")
    assert qpage.status_code == 200 and b"198.51.100.145" in qpage.data

    sd_page = client.get(f"/site/{sid}")
    assert sd_page.status_code == 200 and b"inspectSiteEvent" in sd_page.data and b"cred_trap" in sd_page.data
    assert b"Back to Protected Sites" in sd_page.data
    assert b"sd-blocked-list" in sd_page.data and b"198.51.100.145" in sd_page.data


def test_sites_no_demo_button_and_shield_gated_controls(isolated_shield):
    """Verify /sites has no Demo Website button, /shield disables actions until cloned, and redundant panels stay moved to /site/<id>."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield.cloner.last_status = {"mode": "uninitialized", "domain": "example.com"}
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    sites_page = client.get("/sites")
    assert sites_page.status_code == 200
    assert b"Download Extension" in sites_page.data
    assert b"Open Demo Website" not in sites_page.data
    assert b"Demo Website Setup" not in sites_page.data

    shield_page = client.get("/shield")
    assert shield_page.status_code == 200
    assert b'aria-disabled="true"' in shield_page.data
    assert b"Test Clone /.env Trap" not in shield_page.data
    assert b"Test Clone Login Trap" not in shield_page.data
    assert b"Traffic Routing Decisions" not in shield_page.data
    assert b"Drop-In Website Integration" not in shield_page.data
    assert b"Live Proxy Traffic Decisions" not in shield_page.data
    assert b"Clone-Captured Credentials" not in shield_page.data

    # After cloning, Preview Fake Clone becomes active
    shield.cloner._create_fallback_clone()
    shield_ready = client.get("/shield")
    assert shield_ready.status_code == 200
    assert b'aria-disabled="false"' in shield_ready.data


def test_cold_container_test_absorb_auto_recovers_and_returns_snapshot(isolated_shield):
    """Verify POST /api/site/<id>/test-absorb works even on a cold container and returns full dashboard_data."""
    from dashboard.app import create_app
    from mirage_shield import shield_proxy

    shield, _ = isolated_shield
    shield_proxy._shared_shield_instance = shield
    client = create_app().test_client()

    # Site 'cold-startup-app' was NOT registered on this container yet, but payload passes target_url
    res = client.post("/api/site/cold-startup-app/test-absorb", json={
        "kind": "cred_trap",
        "target_url": "https://cold-startup.app",
        "domain": "cold-startup.app",
    }, headers={"X-MIRAGE-Client-IP": "198.51.100.201"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["dashboard_data"]["total_hits"] == 1
    assert data["dashboard_data"]["creds_captured"] == 1
    assert data["dashboard_data"]["ips_quarantined"] == 1





