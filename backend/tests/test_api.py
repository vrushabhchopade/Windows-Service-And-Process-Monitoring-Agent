import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

init_db()
client = TestClient(app)

def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["database"] == "ONLINE"

def test_dashboard_stats():
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_requests" in data
    assert "blocked_requests" in data
    assert "critical_alerts" in data

def test_dashboard_traffic():
    res = client.get("/api/dashboard/traffic")
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 0
    assert "allowed_rps" in data[0]

def test_attack_distribution():
    res = client.get("/api/dashboard/attack-distribution")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)

def test_inspect_endpoint_clean():
    res = client.post("/api/detection/inspect", json={
        "payload": "clean search query",
        "source_ip": "127.0.0.1",
        "http_method": "GET"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_attack"] is False
    assert data["verdict"] == "ALLOWED"

def test_inspect_endpoint_sqli():
    res = client.post("/api/detection/inspect", json={
        "payload": "admin' OR 1=1--",
        "source_ip": "194.135.24.8",
        "http_method": "POST"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_attack"] is True
    assert data["verdict"] == "BLOCKED"
    assert data["attack_category"] == "SQL Injection"

def test_waf_rules_list():
    res = client.get("/api/waf/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) > 0

def test_rate_limit_api():
    res = client.get("/api/rate-limits")
    assert res.status_code == 200
    data = res.json()
    assert "requests_per_minute" in data

    # Update
    update_res = client.put("/api/rate-limits", json={
        "requests_per_minute": 150,
        "burst_limit": 40,
        "window_seconds": 60,
        "is_active": True,
        "demo_mode": True
    })
    assert update_res.status_code == 200
    assert update_res.json()["requests_per_minute"] == 150

def test_reports_summary_and_export():
    res = client.get("/api/reports/summary")
    assert res.status_code == 200
    assert "total_inspected_requests" in res.json()

    export_res = client.get("/api/reports/export?format=csv")
    assert export_res.status_code == 200
    assert "text/csv" in export_res.headers["content-type"]
