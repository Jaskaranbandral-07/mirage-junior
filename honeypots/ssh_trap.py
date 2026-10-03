import socket
import paramiko
import threading
import time
from database.db_manager import DatabaseManager
from engine.scoring_engine import ScoringEngine
from config.settings import SSH_PORT
import logging

logger = logging.getLogger(__name__)

class FakeShell:
    def __init__(self, channel, ip_address):
        self.channel = channel
        self.ip_address = ip_address
        self.db = DatabaseManager()
        self.scorer = ScoringEngine()
        
    def start(self):
        self.channel.send(b"Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-193-generic x86_64)\r\n")
        self.channel.send(b"root@prod-server:~# ")
        
        start_time = time.time()
        while time.time() - start_time < 10:
            if self.channel.recv_ready():
                cmd = self.channel.recv(1024).decode('utf-8').strip()
                if not cmd:
                    continue
                    
                self.db.log_event(self.ip_address, SSH_PORT, 'SSH', 'shell_command', {'command': cmd}, mitre_id='T1059')
                self.scorer.calculate_threat_score(self.ip_address)
                
                if cmd == 'whoami':
                    self.channel.send(b"root\r\n")
                elif cmd == 'id':
                    self.channel.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                elif cmd == 'uname -a':
                    self.channel.send(b"Linux prod-server 4.15.0 #1 SMP x86_64 GNU/Linux\r\n")
                elif 'cat /etc/passwd' in cmd:
                    self.channel.send(b"root:x:0:0:root:/root:/bin/bash\r\nadmin:x:1000:1000:admin,,,:/home/admin:/bin/bash\r\n")
                    self.db.log_event(self.ip_address, SSH_PORT, 'SSH', 'cat_passwd', {'command': cmd}, mitre_id='T1087.001')
                    self.scorer.calculate_threat_score(self.ip_address)
                elif cmd == 'ls':
                    self.channel.send(b"backup_db.sql config.php \r\n")
                else:
                    self.channel.send(b"bash: " + cmd.encode() + b": command not found\r\n")
                    
                self.channel.send(b"root@prod-server:~# ")
            time.sleep(0.1)
            
        self.channel.send(b"\r\nSegmentation fault (core dumped)\r\n")
        self.channel.close()

class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, ip_address):
        self.event = threading.Event()
        self.ip_address = ip_address
        self.attempts = 0
        self.db = DatabaseManager()
        self.scorer = ScoringEngine()

    def check_auth_password(self, username, password):
        self.attempts += 1
        self.db.log_credential(self.ip_address, 'SSH', username, password)
        self.db.log_event(self.ip_address, SSH_PORT, 'SSH', 'login_attempt', {'user': username}, mitre_id='T1110')
        self.scorer.calculate_threat_score(self.ip_address)
        
        if self.attempts >= 3:
            time.sleep(2)
            return paramiko.AUTH_FAILED
            
        if username in ['root', 'admin'] and password in ['root', 'admin', 'password', '123456']:
            self.db.log_event(self.ip_address, SSH_PORT, 'SSH', 'shell_access', {'user': username}, mitre_id='T1033')
            self.scorer.calculate_threat_score(self.ip_address)
            return paramiko.AUTH_SUCCESSFUL
            
        return paramiko.AUTH_FAILED
        
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
        
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def handle_ssh_connection(client_socket, addr):
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_7.6p1 Ubuntu"
        
        # Need a host key, generating temporary one (in production use saved key)
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        server = SSHServerInterface(addr[0])
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return
            
        channel = transport.accept(20)
        if channel is None:
            return
            
        server.event.wait(10)
        if not server.event.is_set():
            return
            
        fake_shell = FakeShell(channel, addr[0])
        fake_shell.start()
        
    except Exception as e:
        logger.error(f"SSH Handler error: {e}")
    finally:
        try:
            transport.close()
        except:
            pass

def run_ssh_trap():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', SSH_PORT))
        server_socket.listen(100)
        logger.info(f"SSH Trap listening on port {SSH_PORT}")
        
        while True:
            client, addr = server_socket.accept()
            db = DatabaseManager()
            db.log_event(addr[0], SSH_PORT, 'SSH', 'connection', mitre_id='T1046')
            scorer = ScoringEngine()
            scorer.calculate_threat_score(addr[0])
            
            t = threading.Thread(target=handle_ssh_connection, args=(client, addr))
            t.daemon = True
            t.start()
    except Exception as e:
        logger.error(f"SSH server error: {e}")

if __name__ == '__main__':
    run_ssh_trap()
