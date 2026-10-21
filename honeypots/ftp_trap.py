import os
import json
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import threading
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine
from config.settings import FTP_PORT, SCORING_RULES_FILE

try:
    with open(SCORING_RULES_FILE, "r") as f:
        SCORING_RULES = json.load(f)
except Exception:
    SCORING_RULES = {}

class HoneypotFTPHandler(FTPHandler):
    def on_connect(self):
        db = DatabaseManager()
        scorer = ScoringEngine()
        db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'connection', threat_pts=SCORING_RULES.get('connection', 5), mitre_id='T1046')
        scorer.calculate_threat_score(self.remote_ip)
        super().on_connect()

    def on_login(self, username):
        db = DatabaseManager()
        scorer = ScoringEngine()
        threat_pts = SCORING_RULES.get('login_attempt', 8)
        if username == "anonymous":
            db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'login_attempt', {'user': username}, threat_pts=threat_pts)
        else:
            db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'login_attempt', {'user': username}, threat_pts=threat_pts, mitre_id='T1110')
        scorer.calculate_threat_score(self.remote_ip)
        super().on_login(username)

    def on_login_failed(self, username, password):
        db = DatabaseManager()
        scorer = ScoringEngine()
        db.log_credential(self.remote_ip, 'FTP', username, password)
        db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'login_attempt', {'user': username}, threat_pts=SCORING_RULES.get('login_attempt', 8), mitre_id='T1110')
        scorer.calculate_threat_score(self.remote_ip)
        super().on_login_failed(username, password)

    def on_file_sent(self, file):
        db = DatabaseManager()
        scorer = ScoringEngine()
        filename = os.path.basename(file)
        db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'ftp_download', {'file': filename}, threat_pts=SCORING_RULES.get('ftp_download', 15), mitre_id='T1005')
        
        # Threat score updated for download
        if 'credentials' in filename or 'backup' in filename:
            db.log_honeytoken_trigger(filename, 'ftp_file', self.remote_ip)
            db.log_event(self.remote_ip, FTP_PORT, 'FTP', 'honeytoken_trigger', {'file': filename}, threat_pts=SCORING_RULES.get('honeytoken_trigger', 25), mitre_id='T1083')
            
        scorer.calculate_threat_score(self.remote_ip)
        super().on_file_sent(file)

def run_ftp_trap():
    authorizer = DummyAuthorizer()
    
    # Create fake ftp directory
    ftp_dir = os.path.abspath("ftp_root")
    os.makedirs(ftp_dir, exist_ok=True)
    with open(os.path.join(ftp_dir, "credentials.xlsx"), "w") as f:
        f.write("fake credentials")
    with open(os.path.join(ftp_dir, "backup_db_2026.sql"), "w") as f:
        f.write("fake backup")
        
    authorizer.add_anonymous(ftp_dir)
    authorizer.add_user("admin", "12345", ftp_dir, perm="elr")
    
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = "vsFTPd 3.0.3"
    
    server = FTPServer(("0.0.0.0", FTP_PORT), handler)
    server.serve_forever()

if __name__ == '__main__':
    run_ftp_trap()
