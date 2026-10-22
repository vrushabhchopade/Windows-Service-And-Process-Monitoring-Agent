import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

init_db()
client = TestClient(app)

def test_alerts_workflow():
    # 1. Fetch alerts
    res = client.get("/api/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) > 0
    target_id = alerts[0]["id"]

    # 2. Update status to INVESTIGATING
    patch_res = client.patch(f"/api/alerts/{target_id}", json={
        "status": "INVESTIGATING",
        "assignee": "E. Vance"
    })
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"
    assert patch_res.json()["assignee"] == "E. Vance"

    # 3. Add analyst forensic note
    note_res = client.post(f"/api/alerts/{target_id}/notes", json={
        "author": "E. Vance",
        "content": "Automated test note verifying incident response."
    })
    assert note_res.status_code == 200
    assert "Automated test note" in note_res.json()["notes_json"]

def test_ip_block_and_unblock():
    test_ip = "198.51.100.222"

    # Block IP
    block_res = client.post("/api/ips/blocklist", json={
        "ip_address": test_ip,
        "reason": "Pytest automated verification"
    })
    assert block_res.status_code == 200
    assert block_res.json()["is_blocked"] is True

    # Unblock IP
    unblock_res = client.delete(f"/api/ips/blocklist/{test_ip}")
    assert unblock_res.status_code == 200
    assert unblock_res.json()["is_blocked"] is False
