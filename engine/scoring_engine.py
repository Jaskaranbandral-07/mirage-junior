import json
import logging
from config.settings import SCORING_RULES_FILE, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, QUARANTINE_THRESHOLD
import config.settings as settings_cfg

from database.db_manager import DatabaseManager
from engine.quarantine import QuarantineManager
from engine.alert_manager import AlertManager

logger = logging.getLogger(__name__)

# Ensure AlertManager has send_alert method
if not hasattr(AlertManager, 'send_alert'):
    AlertManager.send_alert = AlertManager.send_telegram_alert

class ScoringEngine:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ScoringEngine, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, quarantine_manager=None, alert_manager=None):
        if getattr(self, '_initialized', False):
            if quarantine_manager is not None:
                self.quarantine_manager = quarantine_manager
            if alert_manager is not None:
                self.alert_manager = alert_manager
            return
        self._initialized = True
        self.db = DatabaseManager()
        with open(SCORING_RULES_FILE, "r") as f:
            self.rules = json.load(f)
        self.quarantine_manager = quarantine_manager or QuarantineManager()
        self.alert_manager = alert_manager or AlertManager(bot_token=getattr(settings_cfg, 'TELEGRAM_BOT_TOKEN', TELEGRAM_BOT_TOKEN), chat_id=getattr(settings_cfg, 'TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID))

    @classmethod
    def calculate_threat_score(cls, ip_address):
        instance = cls._instance if cls._instance is not None else cls()
        return instance._calculate_threat_score(ip_address)

    def _calculate_threat_score(self, ip_address):
        events = self.db.get_events_by_ip(ip_address)
        score = 0
        services_hit = set()
        for event in events:
            # Simple addition of base rule scores mapped to event types
            event_type = event.get('event_type')
            if event_type in self.rules:
                score += self.rules[event_type]
            elif event.get('threat_pts'):
                score += int(event['threat_pts'])
            if event.get('port'):
                services_hit.add(event['port'])
        
        # Cross-service hit modifier
        if len(services_hit) > 1:
            score += self.rules.get('lateral_scan', 15)
            
        score = min(score, 100)
        
        classification = self._get_classification(score)
        
        self.db.update_threat_score(ip_address, score, classification)
        
        # Trigger actions based on thresholds
        summary = f"IP {ip_address} classified as {classification} with threat score {score}/100."
        
        # Quarantine attacker if score meets or exceeds threshold (25 pts)
        threshold = getattr(settings_cfg, 'QUARANTINE_THRESHOLD', 25)
        if score >= threshold:
            self.quarantine_manager.block_ip(ip_address, reason=f'Threat score {score} exceeded threshold ({threshold})', threat_score=score)

        # Graded alerts
        if score >= 76:
            self.alert_manager.send_alert(ip_address, 'CRITICAL', score, summary)
        elif score >= 51:
            self.alert_manager.send_alert(ip_address, 'ACTIVE_THREAT', score, summary)
        elif score >= 21:
            self.alert_manager.send_alert(ip_address, 'SUSPICIOUS', score, summary)
            
        return score, classification
        
    def _get_classification(self, score):
        if score <= 20: return "SCANNER"
        elif score <= 50: return "SUSPICIOUS"
        elif score <= 75: return "ACTIVE_THREAT"
        return "CRITICAL"
