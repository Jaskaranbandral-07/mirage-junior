import pytest

# Dummy mock for scoring engine
class ScoringEngine:
    def __init__(self):
        self.score = 0
    def add_event(self, event_type):
        rules = {"http_scan": 5, "env_access": 20, "ssh_brute": 15, "shell": 15}
        self.score += rules.get(event_type, 0)
        self.score = min(self.score, 100)
    def classify(self):
        if self.score >= 76: return "CRITICAL"
        elif self.score >= 51: return "ACTIVE_THREAT"
        elif self.score >= 21: return "SUSPICIOUS"
        return "SCANNER"

def test_scoring_cap():
    engine = ScoringEngine()
    for _ in range(10):
        engine.add_event("ssh_brute")
    assert engine.score == 100

def test_classification():
    engine = ScoringEngine()
    engine.add_event("http_scan")
    assert engine.classify() == "SCANNER"
    engine.add_event("env_access")
    assert engine.classify() == "SUSPICIOUS"
    engine.add_event("ssh_brute")
    engine.add_event("shell")
    assert engine.classify() == "ACTIVE_THREAT"
    engine.add_event("ssh_brute")
    engine.add_event("env_access")
    assert engine.classify() == "CRITICAL"
