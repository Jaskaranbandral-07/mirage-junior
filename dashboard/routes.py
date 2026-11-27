"""
MIRAGE Shield — Dashboard & Multi-Tenant Customer Portal Routes
All route handlers for global telemetry, per-website personal dashboards,
backend SDK ingestion, and deception traps.
"""

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash, Response
import csv
import io
import sqlite3
import json
import os
import time
import zipfile
import config.settings as settings_cfg
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine

dashboard_bp = Blueprint('dashboard', __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST_PATH = os.path.join(BASE_DIR, 'config', 'whitelist.json')

DASHBOARD_UI_ROUTES = {'/', '/attacks', '/quarantine', '/shield', '/sites', '/settings', '/extension'}


def _is_dashboard_route(norm_path: str) -> bool:
    return (
        norm_path in DASHBOARD_UI_ROUTES
        or norm_path.startswith('/attacker/')
        or norm_path.startswith('/site/')
    )


def get_real_client_ip():
    """Extract the real visitor/attacker IP across Vercel, Nginx, or Cloudflare."""
    for header in ('X-MIRAGE-Client-IP', 'X-Vercel-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP', 'X-Forwarded-For'):
        val = request.headers.get(header)
        if val:
            ip = val.split(',')[0].strip()
            if ip:
                return ip
    return request.remote_addr or '127.0.0.1'


def get_db():
    """Get a database connection with Row factory."""
    db_path = getattr(settings_cfg, 'DATABASE_PATH', os.path.join(BASE_DIR, 'database', 'mirage_shield.db'))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@dashboard_bp.before_app_request
def portal_relative_navigation():
    """
    Keep relative JS/HTML navigation originating from inside a cloned customer portal
    (/portal/<domain>) routed inside that customer's deception portal.
    The MIRAGE Shield platform itself never traps or inspects its own routes.
    """
    path = request.path or '/'
    if (
        path.startswith('/static/')
        or path.startswith('/api/')
        or path.startswith('/portal/')
        or path.startswith('/mirage-shield/')
        or path == '/favicon.ico'
        or request.method == 'OPTIONS'
    ):
        return None

    norm_path = '/' + path.strip('/').lower() if path.strip('/') else '/'
    if _is_dashboard_route(norm_path):
        return None

    referer = request.headers.get('Referer', '')
    if '/portal/' in referer:
        try:
            from urllib.parse import urlparse
            ref_path = urlparse(referer).path
            parts = [p for p in ref_path.split('/') if p]
            if len(parts) >= 2 and parts[0] == 'portal':
                domain = parts[1]
                return shield_clean_portal(domain, path.lstrip('/'))
        except Exception:
            pass
    return None



# ─── PAGE ROUTES ────────────────────────────────────────────────────────

@dashboard_bp.route('/')
def overview():
    """Main dashboard overview page."""
    db = get_db()
    # Stats cards
    total_hits = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    unique_ips = db.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
    creds_captured = db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    avg_score_row = db.execute("SELECT AVG(threat_score) FROM attackers WHERE threat_score > 0").fetchone()[0]
    avg_score = int(avg_score_row) if avg_score_row else 0
    quarantined = db.execute("SELECT COUNT(DISTINCT ip_address) FROM quarantine_log WHERE is_active = 1").fetchone()[0]

    # Recent events
    recent_events = [dict(r) for r in db.execute(
        "SELECT e.*, a.country, a.classification FROM events e LEFT JOIN attackers a ON e.ip_address = a.ip_address ORDER BY e.timestamp DESC LIMIT 20"
    ).fetchall()]

    # Quarantine log
    quarantine_log = [dict(r) for r in db.execute(
        "SELECT * FROM quarantine_log WHERE is_active = 1 ORDER BY blocked_at DESC LIMIT 5"
    ).fetchall()]

    db.close()
    return render_template('overview.html',
                           total_hits=total_hits,
                           unique_ips=unique_ips,
                           creds_captured=creds_captured,
                           avg_score=avg_score,
                           quarantined=quarantined,
                           recent_events=recent_events,
                           quarantine_log=quarantine_log,
                           is_vercel=bool(os.getenv('VERCEL')))


@dashboard_bp.route('/attacks')
def attacks():
    """Full attack log page with pagination, search, and protocol filtering."""
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    search = request.args.get('search', '').strip()
    protocol = request.args.get('protocol', '').strip().upper()

    query_parts = []
    params = []

    if search:
        query_parts.append("(e.ip_address LIKE ? OR e.event_type LIKE ? OR e.mitre_id LIKE ? OR a.country LIKE ? OR e.details LIKE ?)")
        wildcard = f'%{search}%'
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])

    if protocol and protocol != 'ALL':
        query_parts.append("e.protocol = ?")
        params.append(protocol)

    where_clause = f"WHERE {' AND '.join(query_parts)}" if query_parts else ""

    # Count matching
    count_sql = f"""SELECT COUNT(*) FROM events e 
                   LEFT JOIN attackers a ON e.ip_address = a.ip_address 
                   {where_clause}"""
    total = db.execute(count_sql, params).fetchone()[0]

    # Fetch 10 records per page
    fetch_sql = f"""SELECT e.*, a.country, a.city, a.classification, a.threat_score FROM events e 
                   LEFT JOIN attackers a ON e.ip_address = a.ip_address 
                   {where_clause}
                   ORDER BY e.timestamp DESC LIMIT ? OFFSET ?"""
    events = [dict(r) for r in db.execute(fetch_sql, params + [per_page, offset]).fetchall()]

    total_pages = max(1, (total + per_page - 1) // per_page)

    # Protocol breakdown counts for filter chips
    counts_raw = db.execute("SELECT protocol, COUNT(*) as c FROM events GROUP BY protocol").fetchall()
    protocol_counts = {r['protocol']: r['c'] for r in counts_raw if r['protocol']}
    total_all = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    db.close()
    return render_template('attacks.html',
                           events=events,
                           page=page,
                           per_page=per_page,
                           total_pages=total_pages,
                           search=search,
                           protocol=protocol,
                           total=total,
                           total_all=total_all,
                           protocol_counts=protocol_counts)



@dashboard_bp.route('/attacker/<ip>')
def attacker(ip):
    """Single attacker deep-dive page with timeline."""
    db = get_db()
    # Attacker profile
    profile = db.execute("SELECT * FROM attackers WHERE ip_address = ?", (ip,)).fetchone()
    profile = dict(profile) if profile else {'ip_address': ip, 'threat_score': 0, 'classification': 'UNKNOWN',
                                              'country': 'Unknown', 'city': '', 'isp': '',
                                              'first_seen': '', 'last_seen': '', 'total_events': 0,
                                              'is_quarantined': 0}

    # Attack timeline events
    events = [dict(r) for r in db.execute(
        "SELECT * FROM events WHERE ip_address = ? ORDER BY timestamp ASC", (ip,)
    ).fetchall()]

    # Credential attempts
    credentials = [dict(r) for r in db.execute(
        "SELECT * FROM credentials WHERE ip_address = ? ORDER BY timestamp DESC", (ip,)
    ).fetchall()]

    # Quarantine history
    quarantine = [dict(r) for r in db.execute(
        "SELECT * FROM quarantine_log WHERE ip_address = ? ORDER BY blocked_at DESC", (ip,)
    ).fetchall()]

    # Calculate running score for timeline
    running_score = 0
    for event in events:
        running_score += event.get('threat_pts', 0)
        running_score = min(running_score, 100)
        event['running_score'] = running_score

    db.close()
    return render_template('attacker.html', ip=ip, profile=profile,
                           events=events, credentials=credentials, quarantine=quarantine)


@dashboard_bp.route('/quarantine')
def quarantine():
    """Quarantine management page."""
    db = get_db()
    active = [dict(r) for r in db.execute(
        "SELECT * FROM quarantine_log WHERE is_active = 1 ORDER BY blocked_at DESC"
    ).fetchall()]
    history = [dict(r) for r in db.execute(
        "SELECT * FROM quarantine_log WHERE is_active = 0 ORDER BY blocked_at DESC LIMIT 50"
    ).fetchall()]
    total_blocked = db.execute("SELECT COUNT(*) FROM quarantine_log").fetchone()[0]
    currently_active = db.execute("SELECT COUNT(DISTINCT ip_address) FROM quarantine_log WHERE is_active = 1").fetchone()[0]
    db.close()
    return render_template('quarantine.html', active=active, history=history,
                           total_blocked=total_blocked, currently_active=currently_active)


@dashboard_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    """Settings configuration page."""
    if request.method == 'POST':
        telegram_bot_token = request.form.get('telegram_bot_token', '').strip()
        telegram_chat_id = request.form.get('telegram_chat_id', '').strip()
        whitelist_ips = request.form.get('whitelist_ips', '')

        # Updates config/settings.py values in memory
        settings_cfg.TELEGRAM_BOT_TOKEN = telegram_bot_token
        settings_cfg.TELEGRAM_CHAT_ID = telegram_chat_id

        if 'quarantine_threshold' in request.form:
            try:
                settings_cfg.QUARANTINE_THRESHOLD = int(request.form.get('quarantine_threshold'))
            except (ValueError, TypeError):
                pass

        # Updates config/whitelist.json with the new whitelist IPs (split by newline)
        whitelist_list = [line.strip() for line in whitelist_ips.splitlines() if line.strip()]
        try:
            with open(WHITELIST_PATH, 'w') as f:
                json.dump(whitelist_list, f, indent=4)
        except Exception:
            pass

        flash('Settings updated successfully.')
        return redirect(url_for('dashboard.settings'))

    # Load current values from config
    telegram_bot_token = getattr(settings_cfg, 'TELEGRAM_BOT_TOKEN', '')
    telegram_chat_id = getattr(settings_cfg, 'TELEGRAM_CHAT_ID', '')
    quarantine_threshold = getattr(settings_cfg, 'QUARANTINE_THRESHOLD', 25)

    whitelist_ips = ""
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, 'r') as f:
                wl = json.load(f)
                if isinstance(wl, list):
                    whitelist_ips = "\n".join(wl)
        except Exception:
            pass

    return render_template('settings.html',
                           telegram_bot_token=telegram_bot_token,
                           telegram_chat_id=telegram_chat_id,
                           whitelist_ips=whitelist_ips,
                           quarantine_threshold=quarantine_threshold)


@dashboard_bp.route('/shield')
def shield_page():
    """MIRAGE Shield Deception-as-a-Service control panel."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    db_mgr = DatabaseManager()
    sites = db_mgr.list_sites()
    return render_template('shield.html', shield_stats=shield.get_full_stats(), sites=sites)


@dashboard_bp.route('/sites')
def sites_hub():
    """Multi-tenant Protected Websites & Customer Workspaces directory."""
    db_mgr = DatabaseManager()
    sites = db_mgr.list_sites()
    demo_target_url = getattr(settings_cfg, 'DEMO_TARGET_URL', '')
    return render_template('sites.html', sites=sites, demo_target_url=demo_target_url,
                           is_vercel=bool(os.getenv('VERCEL')))


@dashboard_bp.route('/extension')
def extension_download_page():
    """Chrome Extension download page + Demo Startup Website launcher for presentations."""
    demo_target_url = getattr(settings_cfg, 'DEMO_TARGET_URL', '')
    return render_template('extension.html', demo_target_url=demo_target_url,
                           is_vercel=bool(os.getenv('VERCEL')))


@dashboard_bp.route('/api/extension/download')
def api_extension_download():
    """Package chrome_extension/ on-the-fly into a clean installable .zip archive."""
    ext_dir = os.path.join(BASE_DIR, 'chrome_extension')
    if not os.path.isdir(ext_dir):
        return jsonify({'error': 'Chrome extension package not found'}), 404

    buf = io.BytesIO()
    skip_names = {'.DS_Store', 'Thumbs.db'}
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for walk_root, _, files in os.walk(ext_dir):
            if '__pycache__' in walk_root:
                continue
            for fname in sorted(files):
                if fname in skip_names or fname.endswith('.pyc'):
                    continue
                full_path = os.path.join(walk_root, fname)
                rel_path = os.path.relpath(full_path, ext_dir).replace('\\', '/')
                zf.write(full_path, arcname=f"mirage-shield-extension/{rel_path}")
    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype='application/zip',
        headers={
            'Content-Disposition': 'attachment; filename="mirage-shield-extension.zip"',
            'Cache-Control': 'no-store',
        },
    )


@dashboard_bp.route('/api/sdk/download/<lang>')
def api_sdk_download(lang):
    """Serve downloadable Backend SDK package (Python WSGI zip or Node.js Express module)."""
    clean_lang = (lang or '').strip().lower()
    sdk_dir = os.path.join(BASE_DIR, 'mirage_shield', 'sdk')
    site_id = (request.args.get('site_id') or '').strip()

    site = None
    if site_id:
        try:
            site = DatabaseManager().get_site(site_id)
        except Exception:
            site = None

    base_url = request.host_url.rstrip('/')
    site_key = site['api_key'] if site else 'ms_live_YOUR_KEY'
    domain = site['domain'] if site else 'your-domain.com'

    if clean_lang in ('node', 'nodejs', 'js'):
        node_path = os.path.join(sdk_dir, 'node_shield.js')
        if not os.path.isfile(node_path):
            return jsonify({'error': 'Node SDK not found'}), 404
        with open(node_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(
            content,
            mimetype='application/javascript',
            headers={
                'Content-Disposition': 'attachment; filename="node_shield.js"',
                'Cache-Control': 'no-store',
            },
        )

    if clean_lang in ('python', 'py', 'flask'):
        py_files = [
            ('mirage_shield/__init__.py', os.path.join(BASE_DIR, 'mirage_shield', '__init__.py')),
            ('mirage_shield/synthetic_deception.py', os.path.join(BASE_DIR, 'mirage_shield', 'synthetic_deception.py')),
            ('mirage_shield/sdk/__init__.py', os.path.join(sdk_dir, '__init__.py')),
            ('mirage_shield/sdk/python_shield.py', os.path.join(sdk_dir, 'python_shield.py')),
        ]
        quickstart = (
            f"# MIRAGE Shield — Python Backend SDK Quickstart ({domain})\n\n"
            "1. Unzip the `mirage_shield/` folder into your Flask / Django / WSGI project root.\n"
            "2. Add these 2 lines right after creating your Flask `app`:\n\n"
            "```python\n"
            "from mirage_shield.sdk.python_shield import protect_flask_app\n\n"
            "protect_flask_app(\n"
            "    app,\n"
            f'    site_key="{site_key}",\n'
            f'    shield_url="{base_url}",\n'
            f'    domain="{domain}",\n'
            ")\n"
            "```\n"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for arc, disk_path in py_files:
                if os.path.isfile(disk_path):
                    zf.write(disk_path, arcname=arc)
            zf.writestr('QUICKSTART.md', quickstart)
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': 'attachment; filename="mirage-shield-python-sdk.zip"',
                'Cache-Control': 'no-store',
            },
        )

    return jsonify({'error': 'Supported SDK downloads: python, node'}), 404


@dashboard_bp.route('/site/<site_id>')
def site_dashboard(site_id):
    """Dedicated Personal Customer Dashboard strictly isolated to one protected website."""
    db_mgr = DatabaseManager()
    site = db_mgr.get_site(site_id)
    if not site:
        return Response("Protected site workspace not found.", status=404)

    # If a customer key query parameter is supplied, enforce tenant access check
    provided_key = request.args.get('key', '').strip()
    if provided_key and provided_key != site['dashboard_key']:
        return Response("403 Forbidden — Invalid customer dashboard key.", status=403)

    site_data = db_mgr.get_site_dashboard_data(site_id)
    base_url = request.host_url.rstrip('/')
    share_url = f"{base_url}/site/{site_id}?key={site['dashboard_key']}"
    portal_url = f"{base_url}/portal/{site['domain']}"
    return render_template(
        'site_dashboard.html',
        site=site,
        site_data=site_data,
        share_url=share_url,
        portal_url=portal_url,
        shield_base_url=base_url,
        customer_mode=bool(provided_key),
    )



# ─── API ROUTES (for AJAX auto-refresh) ────────────────────────────────

@dashboard_bp.route('/api/stats')
def api_stats():
    """JSON stats endpoint for dashboard auto-refresh."""
    db = get_db()
    total_hits = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    unique_ips = db.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
    creds_captured = db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    avg_score_row = db.execute("SELECT AVG(threat_score) FROM attackers WHERE threat_score > 0").fetchone()[0]
    avg_score = int(avg_score_row) if avg_score_row else 0
    quarantined = db.execute("SELECT COUNT(DISTINCT ip_address) FROM quarantine_log WHERE is_active = 1").fetchone()[0]

    # Threat distribution
    scanner = db.execute("SELECT COUNT(*) FROM attackers WHERE classification = 'SCANNER'").fetchone()[0]
    suspicious = db.execute("SELECT COUNT(*) FROM attackers WHERE classification = 'SUSPICIOUS'").fetchone()[0]
    active_threat = db.execute("SELECT COUNT(*) FROM attackers WHERE classification = 'ACTIVE_THREAT'").fetchone()[0]
    critical = db.execute("SELECT COUNT(*) FROM attackers WHERE classification = 'CRITICAL'").fetchone()[0]

    # Top countries
    countries = {}
    for row in db.execute(
        "SELECT country, COUNT(*) as cnt FROM attackers WHERE country IS NOT NULL AND country != '' GROUP BY country ORDER BY cnt DESC LIMIT 5"
    ).fetchall():
        countries[row['country']] = row['cnt']

    # MITRE stats
    mitre_stats = {}
    for row in db.execute(
        "SELECT mitre_id, COUNT(*) as cnt FROM events WHERE mitre_id IS NOT NULL AND mitre_id != '' GROUP BY mitre_id ORDER BY cnt DESC LIMIT 8"
    ).fetchall():
        mitre_stats[row['mitre_id']] = row['cnt']

    # Hourly attack timeline (last 24h)
    hourly = []
    for row in db.execute(
        """SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt 
           FROM events WHERE timestamp >= datetime('now', '-24 hours') 
           GROUP BY hour ORDER BY hour"""
    ).fetchall():
        hourly.append({'hour': row['hour'], 'count': row['cnt']})

    # Recent quarantines
    recent_quarantines = [dict(r) for r in db.execute(
        "SELECT * FROM quarantine_log WHERE is_active = 1 ORDER BY blocked_at DESC LIMIT 5"
    ).fetchall()]

    db.close()
    return jsonify({
        'total_hits': total_hits,
        'unique_ips': unique_ips,
        'creds_captured': creds_captured,
        'avg_threat_score': avg_score,
        'ips_quarantined': quarantined,
        'threat_distribution': {'Scanner': scanner, 'Suspicious': suspicious, 'Active': active_threat, 'Critical': critical},
        'top_countries': countries,
        'mitre_stats': mitre_stats,
        'hourly_timeline': hourly,
        'recent_quarantines': recent_quarantines
    })


@dashboard_bp.route('/api/events')
def api_events():
    """JSON endpoint for live event feed."""
    db = get_db()
    events = [dict(r) for r in db.execute(
        """SELECT e.*, a.country, a.classification FROM events e 
           LEFT JOIN attackers a ON e.ip_address = a.ip_address 
           ORDER BY e.timestamp DESC LIMIT 20"""
    ).fetchall()]
    db.close()
    return jsonify({'events': events})


@dashboard_bp.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock(ip):
    """Manually unblock a quarantined IP across OS firewall, Shield, and DB."""
    from engine.quarantine import QuarantineManager
    from mirage_shield.shield_proxy import get_shield_instance
    site_id = request.args.get('site_id') or (request.get_json(silent=True) or {}).get('site_id')
    try:
        QuarantineManager().unblock_ip(ip, unblocked_by='manual', site_id=site_id)
    except Exception:
        db = get_db()
        db.execute("UPDATE quarantine_log SET is_active = 0, unblocked_by = 'manual' WHERE ip_address = ? AND is_active = 1", (ip,))
        db.execute("UPDATE attackers SET is_quarantined = 0 WHERE ip_address = ?", (ip,))
        db.commit()
        db.close()
    try:
        get_shield_instance().analyzer.unblock_ip(ip)
    except Exception:
        pass
    return jsonify({'status': 'success', 'message': f'IP {ip} has been unblocked.'})


@dashboard_bp.route('/api/export/csv')
def api_export_csv():
    """Export events as properly escaped CSV (optionally filtered by site_id)."""
    site_id = (request.args.get('site_id') or '').strip()
    db = get_db()
    if site_id and site_id != 'global':
        events = db.execute(
            "SELECT e.*, sa.country FROM events e LEFT JOIN site_attackers sa ON e.site_id = sa.site_id AND e.ip_address = sa.ip_address WHERE e.site_id = ? ORDER BY e.timestamp DESC",
            (site_id,),
        ).fetchall()
    else:
        events = db.execute(
            "SELECT e.*, a.country FROM events e LEFT JOIN attackers a ON e.ip_address = a.ip_address ORDER BY e.timestamp DESC"
        ).fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['site_id', 'timestamp', 'ip_address', 'port', 'protocol', 'event_type', 'threat_pts', 'mitre_id', 'country'])
    for e in events:
        writer.writerow([
            e['site_id'] if 'site_id' in e.keys() else 'global',
            e['timestamp'],
            e['ip_address'],
            e['port'],
            e['protocol'],
            e['event_type'],
            e['threat_pts'],
            e['mitre_id'],
            e['country'],
        ])

    fname = f"mirage_shield_{site_id or 'all'}_events.csv"
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={fname}'})


# ─── MULTI-TENANT SITE WORKSPACES & BACKEND SDK INGESTION ───────────────

@dashboard_bp.route('/api/sites')
def api_sites_list():
    """List all registered customer websites with live per-site counters."""
    db_mgr = DatabaseManager()
    return jsonify({'sites': db_mgr.list_sites()})


@dashboard_bp.route('/api/sites/register', methods=['POST'])
def api_sites_register():
    """Register a customer website and issue its API key + private dashboard URL."""
    payload = request.get_json(silent=True) or {}
    target_url = (payload.get('target_url') or payload.get('domain') or '').strip()
    owner_name = (payload.get('owner_name') or 'Customer').strip()
    if not target_url:
        return jsonify({'success': False, 'error': 'target_url or domain is required'}), 400
    try:
        db_mgr = DatabaseManager()
        site = db_mgr.register_or_get_site(target_url, owner_name=owner_name)
        base_url = request.host_url.rstrip('/')
        return jsonify({
            'success': True,
            'site': site,
            'site_id': site['site_id'],
            'api_key': site['api_key'],
            'dashboard_url': f"/site/{site['site_id']}",
            'share_url': f"{base_url}/site/{site['site_id']}?key={site['dashboard_key']}",
            'portal_url': f"/portal/{site['domain']}",
        })
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@dashboard_bp.route('/api/site/<site_id>/stats')
def api_site_stats(site_id):
    """Isolated JSON stats & live feeds for a single customer website."""
    from mirage_shield.shield_proxy import get_shield_instance
    db_mgr = DatabaseManager()
    site = db_mgr.get_site(site_id)
    if not site:
        return jsonify({'error': 'Site not found'}), 404
    data = db_mgr.get_site_dashboard_data(site_id)
    shield = get_shield_instance()
    data['site'] = site
    data['shield_live'] = shield.analyzer.get_recent_analysis(limit=20, site_id=site_id)
    data['shield_creds'] = shield.injector.get_captured_credentials(site_id=site_id)
    return jsonify(data)


@dashboard_bp.route('/api/site/<site_id>/test-absorb', methods=['POST'])
def api_site_test_absorb(site_id):
    """Simulate an absorbed attack on a customer site and return the useless fake payload."""
    from mirage_shield.shield_proxy import get_shield_instance
    db_mgr = DatabaseManager()
    site = db_mgr.get_site(site_id)
    if not site:
        return jsonify({'success': False, 'error': 'Site not found'}), 404

    payload = request.get_json(silent=True) or {}
    attack_kind = payload.get('kind', 'sqli')
    shield = get_shield_instance()
    ip = get_real_client_ip()

    kind_map = {
        'sqli': ('/api/users?id=1\' OR \'1\'=\'1--', ['sql_injection'], 'sql_injection', 'T1190', 25),
        'api_scrape': ('/api/v1/customers', ['targeted_recon'], 'targeted_recon', 'T1087', 20),
        'rce': ('/cmd?exec=whoami', ['command_injection'], 'shell_command', 'T1059', 25),
        'traversal': ('/download?file=../../../../etc/passwd', ['directory_traversal'], 'directory_traversal', 'T1083', 20),
    }
    path, atk_types, ev_type, mitre_id, pts = kind_map.get(attack_kind, kind_map['sqli'])

    body_str, content_type, status_code, fake_count = shield.deception.generate_response(
        path=path, attack_types=atk_types, ip=ip, domain=site['domain']
    )

    db_mgr.log_event(
        ip_address=ip,
        port=443,
        protocol='SHIELD',
        event_type=ev_type,
        details={
            'absorbed': True,
            'site_domain': site['domain'],
            'path': path,
            'fake_records_served': fake_count,
        },
        threat_pts=pts,
        mitre_id=mitre_id,
        site_id=site_id,
    )
    db_mgr.increment_site_deception(site_id, absorbed_delta=1, fake_records_delta=fake_count)
    ScoringEngine().calculate_threat_score(ip, site_id=site_id)

    shield.stats['total_requests'] += 1
    shield.stats['redirected'] += 1
    shield.stats['fake_records_served'] += fake_count

    return jsonify({
        'success': True,
        'site_id': site_id,
        'absorbed_path': path,
        'fake_records_served': fake_count,
        'fake_response_preview': body_str,
        'content_type': content_type,
    })


@dashboard_bp.route('/api/site/<site_id>/clear', methods=['POST'])
def api_site_clear(site_id):
    """Purge telemetry strictly for one customer website."""
    db_mgr = DatabaseManager()
    if not db_mgr.get_site(site_id):
        return jsonify({'status': 'error', 'message': 'Site not found'}), 404
    db_mgr.clear_site_telemetry(site_id)
    return jsonify({'status': 'success', 'message': f'Cleared telemetry for {site_id}.'})


@dashboard_bp.route('/api/site/<site_id>/delete', methods=['POST'])
def api_site_delete(site_id):
    """Delete a customer site workspace."""
    db_mgr = DatabaseManager()
    if not db_mgr.get_site(site_id):
        return jsonify({'status': 'error', 'message': 'Site not found'}), 404
    db_mgr.delete_site(site_id)
    return jsonify({'status': 'success', 'message': f'Deleted workspace {site_id}.'})


@dashboard_bp.route('/api/ingest', methods=['POST'])
def api_ingest_backend_attack():
    """
    Ingestion API for customer backend SDKs (Python WSGI/Flask/FastAPI & Node Express).
    Authenticates X-MIRAGE-Site-Key and stores absorbed attack telemetry strictly
    into that customer's private site workspace.
    """
    payload = request.get_json(silent=True) or {}
    site_key = (request.headers.get('X-MIRAGE-Site-Key') or payload.get('site_key') or '').strip()
    if not site_key:
        return jsonify({'success': False, 'error': 'Missing X-MIRAGE-Site-Key'}), 401

    db_mgr = DatabaseManager()
    site = db_mgr.get_site_by_api_key(site_key)
    if not site:
        return jsonify({'success': False, 'error': 'Invalid site API key'}), 403

    site_id = site['site_id']
    ip = (payload.get('ip') or get_real_client_ip()).strip()
    path = (payload.get('path') or '/').strip()
    method = (payload.get('method') or 'GET').strip().upper()
    score = int(payload.get('score') or 45)
    decision = (payload.get('decision') or 'REDIRECT').upper()
    attack_types = payload.get('attack_types') or []
    fake_count = int(payload.get('fake_records_served') or 0)
    source = payload.get('source') or 'backend_sdk'
    user_agent = (payload.get('user_agent') or '')[:160]

    if 'sql_injection' in attack_types:
        ev_type, mitre_id, pts = 'sql_injection', 'T1190', 25
    elif 'directory_traversal' in attack_types:
        ev_type, mitre_id, pts = 'directory_traversal', 'T1083', 20
    elif 'command_injection' in attack_types:
        ev_type, mitre_id, pts = 'shell_command', 'T1059', 25
    elif 'xss_probe' in attack_types:
        ev_type, mitre_id, pts = 'targeted_recon', 'T1190', 15
    else:
        ev_type, mitre_id, pts = 'targeted_recon', 'T1552.001', 20

    db_mgr.log_event(
        ip_address=ip,
        port=443,
        protocol='SHIELD',
        event_type=ev_type,
        details={
            'absorbed': True,
            'source': source,
            'decision': decision,
            'shield_score': score,
            'path': path,
            'method': method,
            'user_agent': user_agent,
            'fake_records_served': fake_count,
        },
        threat_pts=pts,
        mitre_id=mitre_id,
        site_id=site_id,
    )
    if payload.get('username') or payload.get('password'):
        db_mgr.log_credential(
            ip_address=ip,
            protocol='HTTP',
            username=payload.get('username', ''),
            password=payload.get('password', ''),
            success=False,
            site_id=site_id,
        )

    db_mgr.increment_site_deception(site_id, absorbed_delta=1, fake_records_delta=fake_count)
    ScoringEngine().calculate_threat_score(ip, site_id=site_id)

    return jsonify({'success': True, 'site_id': site_id, 'absorbed': True})


# ─── MIRAGE SHIELD API ROUTES ──────────────────────────────────────────

@dashboard_bp.route('/api/shield/stats')
def api_shield_stats():
    """Combined JSON telemetry for the integrated MIRAGE Shield view."""
    from mirage_shield.shield_proxy import get_shield_instance
    site_id = (request.args.get('site_id') or '').strip() or None
    shield = get_shield_instance()
    data = shield.get_full_stats(site_id=site_id)
    data['recent'] = shield.analyzer.get_recent_analysis(limit=25, site_id=site_id)
    data['credentials'] = shield.injector.get_captured_credentials(site_id=site_id)
    return jsonify(data)


@dashboard_bp.route('/api/shield/clone', methods=['POST'])
def api_shield_clone():
    """Clone a new website URL into MIRAGE Shield's honeypot cache & register its dashboard."""
    from mirage_shield.shield_proxy import get_shield_instance
    payload = request.get_json(silent=True) or {}
    target_url = (payload.get('target_url') or '').strip()
    owner_name = (payload.get('owner_name') or 'Customer').strip()
    shield = get_shield_instance()
    pages_limit = 1 if os.getenv('VERCEL') else 2
    res = shield.switch_and_clone(target_url, max_pages=pages_limit, owner_name=owner_name)
    if res.get('success'):
        res['preview_url'] = f"/portal/{shield.cloner.domain}"
        # Ensure site record exists even if shield had auto_init_backend=False
        if not res.get('site_id'):
            try:
                site = DatabaseManager().register_or_get_site(res['target_url'], owner_name=owner_name)
                res['site'] = site
                res['site_id'] = site['site_id']
                res['api_key'] = site['api_key']
                res['dashboard_url'] = f"/site/{site['site_id']}"
            except Exception:
                pass
    return jsonify(res), (200 if res.get('success') else 400)


@dashboard_bp.route('/api/shield/simulate', methods=['POST'])
def api_shield_simulate():
    """Simulate legitimate vs hostile traffic through MIRAGE Shield."""
    from mirage_shield.shield_proxy import get_shield_instance
    payload = request.get_json(silent=True) or {}
    scenario = payload.get('scenario', 'sqli')
    shield = get_shield_instance()
    return jsonify(shield.run_simulation(scenario))


@dashboard_bp.route('/api/shield/unblock/<ip>', methods=['POST'])
def api_shield_unblock(ip):
    """Unblock an IP quarantined by MIRAGE Shield."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    ok = shield.unblock_ip(ip)
    return jsonify({'success': ok, 'ip': ip})


@dashboard_bp.route('/portal/<domain>', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@dashboard_bp.route('/portal/<domain>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def shield_clean_portal(domain, subpath=''):
    """Serve cloned target pages and subpages seamlessly while scoping traps to that domain's site_id."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    clean_domain = domain.strip().lower()
    ip = get_real_client_ip()
    rel_subpath = ('/' + subpath.lstrip('/')) if subpath else '/'
    target = f"http://{clean_domain}" if clean_domain.startswith(('127.0.0.1', 'localhost')) else f"https://{clean_domain}"

    site_id = 'global'
    db_mgr = DatabaseManager()
    try:
        site = db_mgr.register_or_get_site(target)
        site_id = site['site_id']
    except Exception:
        pass

    # Absorb SQLi / XSS / Traversal / RCE attacks inside cloned portal using useless fake data
    qs = request.query_string.decode('utf-8', errors='ignore')
    body_text = request.get_data(as_text=True) if request.method in ('POST', 'PUT', 'PATCH') else ''
    if qs or any(k in rel_subpath.lower() for k in ('/api', '/graphql', '/cmd', '/shell', '../')):
        decision, score, breakdown = shield.analyzer.analyze(
            ip=ip,
            path=rel_subpath,
            method=request.method,
            user_agent=request.headers.get('User-Agent', ''),
            headers=dict(request.headers),
            query_string=qs,
            body=body_text,
            site_id=site_id,
        )
        if decision in ('REDIRECT', 'BLOCK') and (breakdown.get('attack_types') or rel_subpath.lower().startswith('/api')):
            shield._sync_detection_to_db(
                ip, f"/portal/{clean_domain}{rel_subpath}", request.method,
                score, decision, breakdown, request.headers.get('User-Agent', ''), site_id=site_id
            )
            if decision == 'BLOCK':
                return shield._serve_block_page(ip, score)
            body_str, ct, sc, fake_cnt = shield.deception.generate_response(
                path=rel_subpath, attack_types=breakdown.get('attack_types'), ip=ip, domain=clean_domain
            )
            shield._record_fake_data_metric(site_id, fake_cnt)
            return Response(body_str, status=sc, content_type=ct)

    # Trap sensitive paths or POST form submissions inside the cloned portal
    if shield.injector.is_trap_endpoint(rel_subpath):
        return _handle_live_trap(rel_subpath, site_id=site_id)

    if request.method == 'POST':
        form_data = request.form.to_dict() or request.get_json(silent=True) or {}
        if form_data:
            shield.stats['credentials_captured'] += 1
            content, content_type, status = shield.injector.capture_form_submission(
                ip, f"/portal/{clean_domain}{rel_subpath}", form_data, site_id=site_id
            )
            db_mgr.increment_site_deception(site_id, absorbed_delta=1, fake_records_delta=0)
            return Response(content, status=status, content_type=content_type)

    cloner = shield.get_cloner_for_target(target)

    # Preserve query string when cloning search/tutorial URLs on-demand
    fetch_path = f"{rel_subpath}?{qs}" if qs and rel_subpath != '/' else rel_subpath
    page_file = cloner.get_or_clone_page(fetch_path)
    if not page_file or not os.path.exists(page_file):
        cloner.clone(max_pages=1)
        page_file = cloner.resolve_page_path(rel_subpath)

    if page_file and os.path.exists(page_file):
        with open(page_file, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
        prefixed = cloner.apply_portal_prefix(html, f"/portal/{clean_domain}")
        deceptive = shield.injector.inject_deception_layer(prefixed, ip)
        return Response(deceptive, status=200, content_type='text/html')
    return Response('Clone preview unavailable', status=404)


@dashboard_bp.route('/mirage-shield/api/beacon', methods=['POST'])
def dashboard_beacon_collect():
    """Collect silent behavioral JS telemetry from cloned decoy pages."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    data = request.get_json(silent=True)
    if not data:
        try:
            data = json.loads(request.get_data(as_text=True) or '{}')
        except Exception:
            data = {}
    shield.injector.record_beacon(data, fallback_ip=get_real_client_ip())
    return jsonify({'status': 'recorded'})


@dashboard_bp.route('/api/shield/preview')
def api_shield_preview():
    """Safely preview the cloned deception site HTML."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    req_target = (request.args.get('target') or '').strip()
    if req_target and req_target.rstrip('/') != shield.target_url.rstrip('/'):
        shield.switch_and_clone(req_target, max_pages=1)
    index_path = shield.cloner.get_index_path()
    if not os.path.exists(index_path):
        shield.cloner.clone(max_pages=1)
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
        return Response(shield.injector.inject_deception_layer(html, get_real_client_ip()), status=200, content_type='text/html')
    return Response('Clone preview unavailable', status=404)


@dashboard_bp.route('/api/clear-data', methods=['POST'])
def api_clear_data():
    """Purge all telemetry records from database and reset Shield counters."""
    from mirage_shield.shield_proxy import get_shield_instance
    try:
        db = get_db()
        for table in ('events', 'attackers', 'site_attackers', 'credentials', 'quarantine_log', 'honeytoken_triggers'):
            db.execute(f"DELETE FROM {table}")
        db.execute("UPDATE sites SET total_absorbed = 0, fake_records_served = 0, last_attack_at = NULL")
        db.commit()
        db.close()

        shield = get_shield_instance()
        shield.stats = {k: 0 for k in shield.stats}
        shield.analyzer.request_log.clear()
        shield.analyzer.ip_suspicion.clear()
        shield.analyzer.ip_paths.clear()
        shield.analyzer.trapped_ips.clear()
        shield.analyzer.blocked_ips.clear()
        shield.analyzer.analysis_history.clear()
        shield.injector.injected_credentials.clear()
        shield.injector.beacon_logs.clear()

        return jsonify({'status': 'success', 'message': 'All old/fake data cleared. Capturing real traffic only.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── CUSTOMER PORTAL DECEPTION TRAP HANDLER ─────────────────────────────
# Note: Only invoked inside /portal/<domain>/... for cloned customer sites,
# never mounted on MIRAGE Shield's own platform root.

def _handle_live_trap(trap_path, site_id='global'):
    """Analyze, log, and serve a deception trap inside a customer portal."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    ip = get_real_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    query_string = request.query_string.decode('utf-8', errors='ignore')
    body = request.get_data(as_text=True) if request.method == 'POST' else ''

    decision, score, breakdown = shield.analyzer.analyze(
        ip=ip,
        path=trap_path,
        method=request.method,
        user_agent=user_agent,
        headers=dict(request.headers),
        query_string=query_string,
        body=body,
        site_id=site_id,
    )

    shield.stats['total_requests'] += 1
    if decision == 'BLOCK':
        shield.stats['blocked'] += 1
    else:
        shield.stats['redirected'] += 1
    shield.stats['honeytokens_triggered'] += 1

    post_data = None
    if request.method == 'POST':
        post_data = request.form.to_dict() or request.get_json(silent=True) or None
        if post_data:
            shield.stats['credentials_captured'] += 1

    content, content_type, status = shield.injector.serve_trap(
        trap_path, ip, request.method, post_data, site_id=site_id
    )
    if site_id and site_id != 'global':
        shield._record_fake_data_metric(site_id, 1)
        try:
            DatabaseManager().increment_site_deception(site_id, absorbed_delta=1, fake_records_delta=0)
        except Exception:
            pass
    if decision == 'BLOCK':
        shield._sync_detection_to_db(ip, trap_path, request.method, score, decision, breakdown, user_agent, site_id=site_id)
        return shield._serve_block_page(ip, score)
    if content is None:
        return Response('Not Found', status=404)
    return Response(content, status=status, content_type=content_type)



