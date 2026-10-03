import pytest

def test_honeytoken_trigger():
    # Mock token monitor
    triggers = []
    def trigger(token):
        triggers.append(token)
        
    trigger(".env")
    assert len(triggers) == 1
    assert triggers[0] == ".env"

def test_filesystem_token():
    triggers = []
    def trigger(token):
        triggers.append(token)
        
    trigger("backup_database.sql")
    assert "backup_database.sql" in triggers
