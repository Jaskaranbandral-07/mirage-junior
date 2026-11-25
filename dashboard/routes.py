"""
MIRAGE Junior — Dashboard Routes
All route handlers for the analytics dashboard.
"""

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash, Response
import sqlite3
import json
import os
import time
import config.settings as settings_cfg
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine

dashboard_bp = Blueprint('dashboard', __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST_PATH = os.path.join(BASE_DIR, 'config', 'whitelist.json')

TRAP_ENDPOINTS = {
    '/.env', '/.git/config', '/.git', '/wp-login.php', '/wp-admin',
    '/phpmyadmin', '/phpmyadmin/', '/admin/login', '/api/config', '/api/keys',
    '/backup.sql', '/database.sql', '/dump.sql', '/debug', '/phpinfo.php',
    '/robots.txt', '/server-status'
}

DASHBOARD_UI_ROUTES = {'/', '/attacks', '/quarantine', '/honeytokens', '/shield', '/settings'}


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
    db_path = getattr(settings_cfg, 'DATABASE_PATH', os.path.join(BASE_DIR, 'database', 'mirage_junior.db'))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _record_real_http_attack(ip, path, method, score, decision, breakdown, user_agent, form_data=None):
    """Persist real captured HTTP attack/probe telemetry into SQLite and ScoringEngine."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    shield.stats['total_requests'] += 1
    if decision == 'BLOCK':
        shield.stats['blocked'] += 1
    elif decision == 'REDIRECT':
        shield.stats['redirected'] += 1
    else:
        shield.stats['allowed'] += 1

    # Sync non-benign detections into persistent MIRAGE database
    if decision in ('REDIRECT', 'BLOCK'):
        shield._sync_detection_to_db(ip, path, method, score, decision, breakdown, user_agent)

    if form_data:
        shield.stats['credentials_captured'] += 1
        shield.injector.capture_form_submission(ip, path, form_data)


@dashboard_bp.before_app_request
def capture_real_web_threats():
    """
    Real-time threat inspection on every live request hitting the web app.
    Ignores static assets and dashboard AJAX polling; captures real probes,
    SQLi, XSS, path traversal, and scanner traffic automatically.
    """
    path = request.path or '/'
    if (
        path.startswith('/static/')
        or path.startswith('/api/')
        or path.startswith('/portal/')
        or path.startswith('/mirage-shield/')
        or path == '/favicon.ico'
    ):
        return None
    if request.method == 'OPTIONS':
        return None

    norm_path = '/' + path.strip('/').lower() if path.strip('/') else '/'
    # Explicit trap routes handle their own logging + trap response
    if norm_path in TRAP_ENDPOINTS or path.lower() in TRAP_ENDPOINTS:
        return None

    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    ip = get_real_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    query_string = request.query_string.decode('utf-8', errors='ignore')
    body = request.get_data(as_text=True) if request.method in ('POST', 'PUT', 'PATCH') else ''

    # Skip scanning normal clean dashboard navigation unless it carries an attack payload or bad UA
    if norm_path in DASHBOARD_UI_ROUTES and not query_string and not body:
        ua_score = shield.analyzer._score_user_agent(user_agent)
        if ua_score < 20:
            shield.stats['total_requests'] += 1
            shield.stats['allowed'] += 1
            return None

    decision, score, breakdown = shield.analyzer.analyze(
        ip=ip,
        path=path,
        method=request.method,
        user_agent=user_agent,
        headers=dict(request.headers),
        query_string=query_string,
        body=body,
    )

    if decision in ('REDIRECT', 'BLOCK'):
        _record_real_http_attack(ip, path, request.method, score, decision, breakdown, user_agent)
        # Do not lock out clean dashboard UI pages themselves, only block attack requests or unknown trap paths
        if decision == 'BLOCK' and norm_path not in DASHBOARD_UI_ROUTES:
            return shield._serve_block_page(ip, score)
        if norm_path not in DASHBOARD_UI_ROUTES and not norm_path.startswith('/attacker/'):
            return shield._serve_honeypot(ip, path, request.method)
    else:
        shield.stats['total_requests'] += 1
        shield.stats['allowed'] += 1
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
    quarantined = db.execute("SELECT COUNT(*) FROM quarantine_log WHERE is_active = 1").fetchone()[0]

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
                           quarantine_log=quarantine_log)


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
    currently_active = db.execute("SELECT COUNT(*) FROM quarantine_log WHERE is_active = 1").fetchone()[0]
    db.close()
    return render_template('quarantine.html', active=active, history=history,
                           total_blocked=total_blocked, currently_active=currently_active)


@dashboard_bp.route('/honeytokens')
def honeytokens():
    """Honeytoken status and trigger history."""
    db = get_db()
    triggers = [dict(r) for r in db.execute(
        "SELECT * FROM honeytoken_triggers ORDER BY timestamp DESC"
    ).fetchall()]
    # Token inventory
    tokens = [
        {'name': '.env', 'type': 'http_endpoint', 'path': '/honeypots/templates/env_file.txt', 'status': 'Active'},
        {'name': 'credentials.xlsx', 'type': 'ftp_file', 'path': '/bait/', 'status': 'Active'},
        {'name': 'backup_database.sql', 'type': 'filesystem', 'path': '/bait/backup_database.sql', 'status': 'Active'},
        {'name': 'admin_passwords.txt', 'type': 'filesystem', 'path': '/bait/admin_passwords.txt', 'status': 'Active'},
        {'name': 'id_rsa', 'type': 'filesystem', 'path': '/bait/ssh_keys/id_rsa', 'status': 'Active'},
    ]
    # Count triggers per token
    for token in tokens:
        count = db.execute(
            "SELECT COUNT(*) FROM honeytoken_triggers WHERE token_name = ?", (token['name'],)
        ).fetchone()[0]
        token['trigger_count'] = count
        token['token_name'] = token['name']
        token['token_type'] = token['type']
    db.close()
    return render_template('honeytokens.html', triggers=triggers, tokens=tokens)


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
    return render_template('shield.html', shield_stats=shield.get_full_stats())



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
    quarantined = db.execute("SELECT COUNT(*) FROM quarantine_log WHERE is_active = 1").fetchone()[0]

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
    """Manually unblock a quarantined IP."""
    db = get_db()
    db.execute("UPDATE quarantine_log SET is_active = 0, unblocked_by = 'manual' WHERE ip_address = ? AND is_active = 1", (ip,))
    db.execute("UPDATE attackers SET is_quarantined = 0 WHERE ip_address = ?", (ip,))
    db.commit()
    db.close()
    return jsonify({'status': 'success', 'message': f'IP {ip} has been unblocked.'})


@dashboard_bp.route('/api/export/csv')
def api_export_csv():
    """Export all events as CSV."""
    db = get_db()
    events = db.execute(
        "SELECT e.*, a.country FROM events e LEFT JOIN attackers a ON e.ip_address = a.ip_address ORDER BY e.timestamp DESC"
    ).fetchall()
    db.close()

    csv_lines = ['timestamp,ip_address,port,protocol,event_type,threat_pts,mitre_id,country']
    for e in events:
        csv_lines.append(f"{e['timestamp']},{e['ip_address']},{e['port']},{e['protocol']},{e['event_type']},{e['threat_pts']},{e['mitre_id']},{e['country']}")

    from flask import Response
    return Response('\n'.join(csv_lines), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=mirage_events.csv'})


@dashboard_bp.route('/api/simulate-attack', methods=['POST'])
def api_simulate_attack():
    """Trigger a live realistic attack capture for demonstration & verification."""
    data = request.get_json(silent=True) or {}
    attack_type = data.get('type') or request.args.get('type', 'sqli')

    attack_presets = {
        'sqli': {
            'ip': '185.220.101.45',
            'country': 'Germany',
            'city': 'Frankfurt',
            'port': 8080,
            'protocol': 'HTTP',
            'event_type': 'sql_injection',
            'details': {'path': '/phpmyadmin/', 'payload': "admin' OR '1'='1'--", 'method': 'POST'},
            'threat_pts': 20,
            'mitre_id': 'T1190'
        },
        'ssh': {
            'ip': '194.26.29.112',
            'country': 'Russia',
            'city': 'Moscow',
            'port': 2222,
            'protocol': 'SSH',
            'event_type': 'brute_force',
            'details': {'service': 'SSH', 'user': 'root', 'pwd_attempts': 14, 'action': 'dictionary_attack'},
            'threat_pts': 30,
            'mitre_id': 'T1110.001'
        },
        'honeytoken': {
            'ip': '45.155.205.233',
            'country': 'Netherlands',
            'city': 'Amsterdam',
            'port': 8080,
            'protocol': 'HONEYTOKEN',
            'event_type': 'honeytoken_access',
            'details': {'file': '.env', 'accessed_key': 'AWS_SECRET_ACCESS_KEY', 'action': 'tripwire_tripped'},
            'threat_pts': 40,
            'mitre_id': 'T1552.001'
        },
        'traversal': {
            'ip': '103.203.57.18',
            'country': 'India',
            'city': 'Mumbai',
            'port': 8080,
            'protocol': 'HTTP',
            'event_type': 'directory_traversal',
            'details': {'path': '../../../../etc/passwd', 'status': 'blocked'},
            'threat_pts': 15,
            'mitre_id': 'T1083'
        }
    }

    preset = attack_presets.get(attack_type, attack_presets['sqli'])
    ip = preset['ip']

    try:
        db_mgr = DatabaseManager()
        scorer = ScoringEngine()

        # Log attack event
        db_mgr.log_event(
            ip_address=ip,
            port=preset['port'],
            protocol=preset['protocol'],
            event_type=preset['event_type'],
            details=preset['details'],
            threat_pts=preset['threat_pts'],
            mitre_id=preset['mitre_id']
        )

        # Log credential attempt if applicable
        if attack_type == 'ssh':
            db_mgr.log_credential(ip, 'SSH', 'root', 'admin1234', success=False)
        elif attack_type == 'sqli':
            db_mgr.log_credential(ip, 'HTTP', "admin' OR 1=1--", "password123", success=False)

        # Recalculate threat score & quarantine if >= 25
        scorer.calculate_threat_score(ip)

        conn = db_mgr.get_connection()
        conn.row_factory = sqlite3.Row
        attacker = conn.execute("SELECT threat_score, classification, is_quarantined FROM attackers WHERE ip_address = ?", (ip,)).fetchone()
        conn.close()

        threat_score = attacker['threat_score'] if attacker else preset['threat_pts']
        is_quarantined = bool(attacker['is_quarantined']) if attacker else False

        return jsonify({
            'status': 'success',
            'message': f"Threat capture recorded: {preset['event_type']} from {ip}",
            'event': {
                'ip': ip,
                'country': preset['country'],
                'protocol': preset['protocol'],
                'event_type': preset['event_type'],
                'threat_pts': preset['threat_pts'],
                'threat_score': threat_score,
                'quarantined': is_quarantined
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── MIRAGE SHIELD API ROUTES ──────────────────────────────────────────

@dashboard_bp.route('/api/shield/stats')
def api_shield_stats():
    """Combined JSON telemetry for the integrated MIRAGE Shield view."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    data = shield.get_full_stats()
    data['recent'] = shield.analyzer.get_recent_analysis(limit=25)
    data['credentials'] = shield.injector.get_captured_credentials()
    return jsonify(data)


@dashboard_bp.route('/api/shield/clone', methods=['POST'])
def api_shield_clone():
    """Clone a new website URL into MIRAGE Shield's honeypot cache."""
    from mirage_shield.shield_proxy import get_shield_instance
    payload = request.get_json(silent=True) or {}
    target_url = (payload.get('target_url') or '').strip()
    shield = get_shield_instance()
    pages_limit = 1 if os.getenv('VERCEL') else 2
    res = shield.switch_and_clone(target_url, max_pages=pages_limit)
    if res.get('success'):
        res['preview_url'] = f"/portal/{shield.cloner.domain}"
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


@dashboard_bp.route('/portal/<path:domain>')
def shield_clean_portal(domain):
    """Serve the pixel-accurate cloned website on a clean domain path."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    clean_domain = domain.split('/')[0].strip()
    target = f"https://{clean_domain}" if not clean_domain.startswith(('127.0.0.1', 'localhost')) else f"http://{clean_domain}"
    if shield.cloner.domain != clean_domain or not os.path.exists(shield.cloner.get_index_path()):
        shield.switch_and_clone(target, max_pages=1)
    index_path = shield.cloner.get_index_path()
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
        deceptive = shield.injector.inject_deception_layer(html, get_real_client_ip())
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


@dashboard_bp.route('/login', methods=['GET', 'POST'])
def cloned_form_trap():
    """Capture credentials submitted from any cloned website login form."""
    from mirage_shield.shield_proxy import get_shield_instance
    shield = get_shield_instance()
    ip = get_real_client_ip()
    if request.method == 'POST':
        form_data = request.form.to_dict() or request.get_json(silent=True) or {}
        if form_data:
            shield.stats['credentials_captured'] += 1
            content, content_type, status = shield.injector.capture_form_submission(ip, '/login', form_data)
            return Response(content, status=status, content_type=content_type)
    return _handle_live_trap('/admin/login')


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
        for table in ('events', 'attackers', 'credentials', 'quarantine_log', 'honeytoken_triggers'):
            db.execute(f"DELETE FROM {table}")
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


# ─── LIVE REAL-CAPTURE HONEYPOT TRAP ROUTES ─────────────────────────────

def _handle_live_trap(trap_path):
    """Analyze, log, and serve a live honeypot trap directly on the web app."""
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
        trap_path, ip, request.method, post_data
    )
    if decision == 'BLOCK':
        shield._sync_detection_to_db(ip, trap_path, request.method, score, decision, breakdown, user_agent)
        return shield._serve_block_page(ip, score)
    if content is None:
        return Response('Not Found', status=404)
    return Response(content, status=status, content_type=content_type)


@dashboard_bp.route('/.env')
def live_trap_env():
    return _handle_live_trap('/.env')


@dashboard_bp.route('/.git/config')
@dashboard_bp.route('/.git')
def live_trap_git():
    return _handle_live_trap('/.git/config')


@dashboard_bp.route('/wp-login.php', methods=['GET', 'POST'])
@dashboard_bp.route('/wp-admin', methods=['GET', 'POST'])
def live_trap_wp():
    return _handle_live_trap('/wp-login.php')


@dashboard_bp.route('/phpmyadmin/', methods=['GET', 'POST'])
@dashboard_bp.route('/phpmyadmin', methods=['GET', 'POST'])
def live_trap_pma():
    return _handle_live_trap('/phpmyadmin')


@dashboard_bp.route('/admin/login', methods=['GET', 'POST'])
def live_trap_admin():
    return _handle_live_trap('/admin/login')


@dashboard_bp.route('/api/config')
def live_trap_api_config():
    return _handle_live_trap('/api/config')


@dashboard_bp.route('/api/keys')
def live_trap_api_keys():
    return _handle_live_trap('/api/keys')


@dashboard_bp.route('/backup.sql')
@dashboard_bp.route('/database.sql')
@dashboard_bp.route('/dump.sql')
def live_trap_sql():
    return _handle_live_trap('/backup.sql')


@dashboard_bp.route('/debug')
def live_trap_debug():
    return _handle_live_trap('/debug')


@dashboard_bp.route('/phpinfo.php')
def live_trap_phpinfo():
    return _handle_live_trap('/phpinfo.php')


@dashboard_bp.route('/robots.txt')
def live_trap_robots():
    return _handle_live_trap('/robots.txt')



