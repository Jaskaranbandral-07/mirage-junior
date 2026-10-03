import time
import requests
import paramiko
import sys

def print_step(msg, color="\033[92m"):
    print(f"{color}[*] {msg}\033[0m")

def simulate_attack(target="127.0.0.1"):
    print_step(f"Starting simulated attack against {target}...")
    
    # Phase 1: HTTP Recon
    print_step("Phase 1: HTTP Recon scanning...", "\033[93m")
    try:
        requests.get(f"http://{target}:8080/robots.txt", timeout=2)
        time.sleep(1)
        requests.get(f"http://{target}:8080/wp-login.php", timeout=2)
        time.sleep(1)
        requests.get(f"http://{target}:8080/.env", timeout=2)
    except:
        pass
    
    # Phase 2: SSH Brute Force
    print_step("Phase 2: SSH Brute Force...", "\033[91m")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target, port=2222, username="root", password="password", timeout=3)
    except:
        pass
        
    print_step("Attack simulation complete! Check the dashboard.", "\033[92m")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    simulate_attack(target)
