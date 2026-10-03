from flask import Flask, request, make_response, render_template, jsonify
import time
import os
import threading
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine
from config.settings import HTTP_PORT

app = Flask(__name__, template_folder='templates')
db = DatabaseManager()
scorer = ScoringEngine()

def log_interaction(event_type, details=None, mitre_id=None):
    ip = request.remote_addr
    db.log_event(ip, HTTP_PORT, 'HTTP', event_type, details, 0, mitre_id)
    scorer.calculate_threat_score(ip)

@app.after_request
def add_headers(response):
    response.headers['X-Powered-By'] = 'PHP/7.4'
    response.headers['Server'] = 'Apache/2.4.41'
    time.sleep(0.2) # artificial delay
    return response

@app.route('/')
def index():
    log_interaction('connection', {'path': '/'}, 'T1046')
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        db.log_credential(request.remote_addr, 'HTTP', request.form.get('username'), request.form.get('password'))
        log_interaction('login_attempt', {'path': '/admin', 'method': 'POST'}, 'T1110')
        return "Invalid credentials, please try again", 401
    log_interaction('connection', {'path': '/admin'}, 'T1046')
    return render_template('admin_login.html')

@app.route('/wp-login.php', methods=['GET', 'POST'])
def wp_login():
    if request.method == 'POST':
        db.log_credential(request.remote_addr, 'HTTP', request.form.get('log'), request.form.get('pwd'))
        log_interaction('login_attempt', {'path': '/wp-login.php', 'method': 'POST'}, 'T1110')
        return "Invalid credentials, please try again", 401
    log_interaction('connection', {'path': '/wp-login.php'}, 'T1046')
    return render_template('wp_login.html')

@app.route('/phpmyadmin/', methods=['GET', 'POST'])
def phpmyadmin():
    if request.method == 'POST':
        log_interaction('login_attempt', {'path': '/phpmyadmin/', 'method': 'POST'}, 'T1110')
        return "Invalid credentials, please try again", 401
    log_interaction('connection', {'path': '/phpmyadmin/'}, 'T1046')
    return "phpMyAdmin interface placeholder"

@app.route('/api/config')
def api_config():
    log_interaction('targeted_recon', {'path': '/api/config'}, 'T1552.001')
    return jsonify({"db": "localhost", "status": "running"})

@app.route('/robots.txt')
def robots():
    log_interaction('lateral_scan', {'path': '/robots.txt'}, 'T1046')
    return "User-agent: *\nDisallow: /admin\nDisallow: /.env"

@app.route('/.env')
def env_file():
    log_interaction('honeytoken_trigger', {'path': '/.env'}, 'T1552.001')
    db.log_honeytoken_trigger('.env', 'http_endpoint', request.remote_addr)
    return render_template('env_file.txt'), 200, {'Content-Type': 'text/plain'}

def run_http_decoy():
    app.run(host='0.0.0.0', port=HTTP_PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    run_http_decoy()
