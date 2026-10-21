"""
MIRAGE Junior — Dashboard Routes
All route handlers for the analytics dashboard.
"""

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
import sqlite3
import json
import os
import config.settings as settings_cfg

dashboard_bp = Blueprint('dashboard', __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST_PATH = os.path.join(BASE_DIR, 'config', 'whitelist.json')


def get_db():
    """Get a database connection with Row factory."""
    db_path = getattr(settings_cfg, 'DATABASE_PATH', os.path.join(BASE_DIR, 'database', 'mirage_junior.db'))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn



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
    quarantine_threshold = getattr(settings_cfg, 'QUARANTINE_THRESHOLD', 76)

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
