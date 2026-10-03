import json
from config.settings import SCORING_RULES_FILE
from database.db_manager import DatabaseManager

class ScoringEngine:
    def __init__(self):
        self.db = DatabaseManager()
        with open(SCORING_RULES_FILE, "r") as f:
            self.rules = json.load(f)

    def calculate_threat_score(self, ip_address):
        events = self.db.get_events_by_ip(ip_address)
        score = 0
        services_hit = set()
        for event in events:
            # Simple addition of base rule scores mapped to event types
            event_type = event.get('event_type')
            if event_type in self.rules:
                score += self.rules[event_type]
            if event.get('port'):
                services_hit.add(event['port'])
        
        # Cross-service hit modifier
        if len(services_hit) > 1:
            score += self.rules.get('lateral_scan', 15)
            
        score = min(score, 100)
        
        classification = self._get_classification(score)
        
        self.db.update_threat_score(ip_address, score, classification)
        
        # Trigger actions based on thresholds
        if score >= 76:
            # Trigger quarantine logic (handled via upper layers/hooks or here if imported)
            pass
            
        return score, classification
        
    def _get_classification(self, score):
        if score <= 20: return "SCANNER"
        elif score <= 50: return "SUSPICIOUS"
        elif score <= 75: return "ACTIVE_THREAT"
        return "CRITICAL"
