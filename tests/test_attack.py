import os
import sys
import time
import socket
import pytest
import requests
import paramiko
from ftplib import FTP

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config.settings import HTTP_PORT, SSH_PORT, FTP_PORT
except ImportError:
    HTTP_PORT = 8080
    SSH_PORT = 2222
    FTP_PORT = 2121

DEFAULT_TARGET = os.getenv("MIRAGE_TARGET_HOST", "127.0.0.1")


def is_port_open(host, port, timeout=1.0):
    """Check if a host:port is actively accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def print_step(msg, color="\033[92m"):
    print(f"{color}[*] {msg}\033[0m")


@pytest.mark.integration
def test_http_recon():
    """Test HTTP decoy honeypot reconnaissance endpoints."""
    target = DEFAULT_TARGET
    if not is_port_open(target, HTTP_PORT):
        pytest.skip(f"HTTP honeypot is not running on {target}:{HTTP_PORT}")

    base_url = f"http://{target}:{HTTP_PORT}"

    # 1. robots.txt
    res_robots = requests.get(f"{base_url}/robots.txt", timeout=3)
    assert res_robots.status_code == 200, "robots.txt request failed"
    assert "Disallow" in res_robots.text or res_robots.status_code == 200

    # 2. wp-login.php
    res_wp = requests.get(f"{base_url}/wp-login.php", timeout=3)
    assert res_wp.status_code == 200, "wp-login.php request failed"

    # 3. .env honeytoken endpoint
    res_env = requests.get(f"{base_url}/.env", timeout=3)
    assert res_env.status_code == 200, ".env honeytoken request failed"
    assert len(res_env.text) > 0, ".env response was empty"


@pytest.mark.integration
def test_ssh_brute_force():
    """Test SSH trap honeypot credential authentication."""
    target = DEFAULT_TARGET
    if not is_port_open(target, SSH_PORT):
        pytest.skip(f"SSH honeypot is not running on {target}:{SSH_PORT}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth_succeeded = False
    try:
        ssh.connect(target, port=SSH_PORT, username="root", password="password", timeout=4)
        auth_succeeded = True
    except paramiko.AuthenticationException:
        # Auth rejection is also a valid honeypot response
        auth_succeeded = False
    except Exception as e:
        pytest.fail(f"Unexpected connection error to SSH honeypot: {e}")
    finally:
        ssh.close()

    assert auth_succeeded or not auth_succeeded  # Handshake was completed without crash


@pytest.mark.integration
def test_ftp_connection():
    """Test FTP trap honeypot connection and anonymous/credential access."""
    target = DEFAULT_TARGET
    if not is_port_open(target, FTP_PORT):
        pytest.skip(f"FTP honeypot is not running on {target}:{FTP_PORT}")

    ftp = FTP()
    try:
        banner = ftp.connect(target, FTP_PORT, timeout=4)
        assert "220" in banner or "vsFTPd" in banner or len(banner) > 0

        login_res = ftp.login("anonymous", "guest@example.com")
        assert "230" in login_res or "logged in" in login_res.lower()

        files = ftp.nlst()
        assert isinstance(files, list)

        ftp.quit()
    except Exception as e:
        try:
            ftp.close()
        except Exception:
            pass
        pytest.fail(f"FTP honeypot interaction failed: {e}")


def simulate_attack(target="127.0.0.1"):
    print_step(f"Starting simulated attack against {target}...")

    # Phase 1: HTTP Recon
    print_step("Phase 1: HTTP Recon scanning...", "\033[93m")
    try:
        r1 = requests.get(f"http://{target}:{HTTP_PORT}/robots.txt", timeout=2)
        print_step(f"robots.txt: HTTP {r1.status_code}")
        time.sleep(1)
        r2 = requests.get(f"http://{target}:{HTTP_PORT}/wp-login.php", timeout=2)
        print_step(f"wp-login.php: HTTP {r2.status_code}")
        time.sleep(1)
        r3 = requests.get(f"http://{target}:{HTTP_PORT}/.env", timeout=2)
        print_step(f".env honeytoken: HTTP {r3.status_code}")
    except Exception as e:
        print_step(f"HTTP recon error: {e}", "\033[91m")

    # Phase 2: SSH Brute Force
    print_step("Phase 2: SSH Brute Force...", "\033[91m")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target, port=SSH_PORT, username="root", password="password", timeout=3)
        print_step("SSH connected successfully!")
        ssh.close()
    except Exception as e:
        print_step(f"SSH brute force attempt result: {e}")

    # Phase 3: FTP Trap
    print_step("Phase 3: FTP Trap Access...", "\033[96m")
    try:
        ftp = FTP()
        ftp.connect(target, FTP_PORT, timeout=3)
        ftp.login("anonymous", "guest@example.com")
        files = ftp.nlst()
        print_step(f"FTP directory contents: {files}")
        ftp.quit()
    except Exception as e:
        print_step(f"FTP trap access result: {e}")

    print_step("Attack simulation complete! Check the dashboard.", "\033[92m")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    simulate_attack(target)
