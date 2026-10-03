import os
import subprocess
import json
import logging
from datetime import datetime, timedelta
from database.db_manager import DatabaseManager
from config.settings import QUARANTINE_DURATION

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuarantineManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.whitelist = self._load_whitelist()

    def _load_whitelist(self):
        whitelist_file = os.path.join("config", "whitelist.json")
        try:
            with open(whitelist_file, "r") as f:
                return set(json.load(f))
        except:
            return set()

    def is_whitelisted(self, ip_address):
        if ip_address in self.whitelist:
            return True
        # For simplicity, assuming exact matches or very basic network checks here
        for w_ip in self.whitelist:
            if ip_address.startswith(w_ip.split("/")[0][:5]):
                # Simplified check for /8, /16 etc.
                pass
        return False

    def block_ip(self, ip_address, reason="Critical Threat", threat_score=100):
        if self.is_whitelisted(ip_address):
            logger.info(f"Cannot block {ip_address} - Whitelisted")
            return False

        logger.info(f"Attempting to block IP: {ip_address}")
        success = False
        try:
            if os.name == 'nt':
                cmd = f'netsh advfirewall firewall add rule name="MIRAGE_BLOCK_{ip_address}" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            else:
                cmd = f'iptables -A INPUT -s {ip_address} -j DROP'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            success = True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP due to permissions: {e}")
            # Graceful degradation - log it anyway
        except Exception as e:
            logger.error(f"Error blocking IP: {e}")

        expires_at = datetime.now() + timedelta(seconds=QUARANTINE_DURATION)
        self.db.quarantine_ip(ip_address, reason, threat_score, expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        return success

    def unblock_ip(self, ip_address, unblocked_by='manual'):
        logger.info(f"Attempting to unblock IP: {ip_address}")
        success = False
        try:
            if os.name == 'nt':
                cmd = f'netsh advfirewall firewall delete rule name="MIRAGE_BLOCK_{ip_address}"'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            else:
                cmd = f'iptables -D INPUT -s {ip_address} -j DROP'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            success = True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP: {e}")
        except Exception as e:
            logger.error(f"Error unblocking IP: {e}")

        self.db.unquarantine_ip(ip_address, unblocked_by)
        return success

    def check_expired(self):
        records = self.db.get_quarantine_log()
        now = datetime.now()
        for rec in records:
            if rec['is_active']:
                expires_at = datetime.strptime(rec['expires_at'], '%Y-%m-%d %H:%M:%S')
                if now > expires_at:
                    self.unblock_ip(rec['ip_address'], 'auto_expire')
