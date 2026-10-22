import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, Index
from app.database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    event_type = Column(String(50), default="ATTACK_ATTEMPT", index=True)
    source_ip = Column(String(45), index=True)
    attack_category = Column(String(50), index=True)  # SQLi, XSS, Path Traversal, Command Injection, etc.
    severity = Column(String(20), index=True)         # CRITICAL, HIGH, MEDIUM, LOW
    matched_rule_id = Column(String(50), index=True)  # e.g., WAF-SQLI-001
    matched_pattern = Column(String(255))
    payload_snippet = Column(Text)                    # Safe sanitized snippet
    action_taken = Column(String(20), default="BLOCKED", index=True) # BLOCKED, FLAGGED, ALLOWED, SANITIZED
    confidence_score = Column(Float, default=0.95)
    request_path = Column(String(500))
    http_method = Column(String(10), default="GET")
    user_agent = Column(String(500))
    is_demo = Column(Boolean, default=True)


class HTTPRequestLog(Base):
    __tablename__ = "http_request_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    http_method = Column(String(10), index=True)
    path = Column(String(500), index=True)
    query_params = Column(Text, default="")
    status_code = Column(Integer, index=True)
    latency_ms = Column(Float, default=1.0)
    user_agent = Column(String(500), default="")
    headers_json = Column(Text, default="{}")
    body_snippet = Column(Text, default="")
    action = Column(String(20), default="ALLOWED", index=True) # ALLOWED, BLOCKED, THROTTLED
    threat_vector = Column(String(100), default="CLEAN")
    country_code = Column(String(10), default="US")
    asn_org = Column(String(100), default="Enterprise Edge")
    is_demo = Column(Boolean, default=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_code = Column(String(30), unique=True, index=True) # e.g. ALT-8821
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(50), index=True)               # Credential Stuffing, SQLi Cluster, RCE Vector
    severity = Column(String(20), index=True)               # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), default="NEW", index=True)  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    target_endpoint = Column(String(255))
    source_ip = Column(String(45), index=True)
    unique_ip_count = Column(Integer, default=1)
    velocity_rps = Column(Float, default=0.0)
    confidence_score = Column(Float, default=0.90)
    assignee = Column(String(100), default="Unassigned")
    notes_json = Column(Text, default="[]")                 # Array of note objects
    is_demo = Column(Boolean, default=True)


class WAFRule(Base):
    __tablename__ = "waf_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(50), unique=True, index=True)  # WAF-SQLI-001
    name = Column(String(150), nullable=False)
    description = Column(Text)
    category = Column(String(50), index=True)              # SQLi, XSS, Path Traversal, Command Injection, etc.
    pattern = Column(Text, nullable=False)                 # Regex or keyword definition
    severity = Column(String(20), default="HIGH")          # CRITICAL, HIGH, MEDIUM, LOW
    default_action = Column(String(20), default="BLOCK")   # BLOCK, FLAG, LOG
    is_active = Column(Boolean, default=True, index=True)
    hits_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class IPReputation(Base):
    __tablename__ = "ip_reputations"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    reputation_score = Column(Integer, default=0)          # 0-100 (higher = more malicious)
    classification = Column(String(50), default="CLEAN")   # MALICIOUS, SUSPICIOUS, CLEAN, TOR_EXIT_NODE
    country = Column(String(50), default="Unknown")
    asn = Column(String(100), default="Unknown")
    total_requests = Column(Integer, default=0)
    total_blocks = Column(Integer, default=0)
    is_blocked = Column(Boolean, default=False, index=True)
    block_reason = Column(String(255), default="")
    blocked_at = Column(DateTime, nullable=True)


class RateLimitConfiguration(Base):
    __tablename__ = "rate_limit_configurations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), default="Default Edge Policy")
    requests_per_minute = Column(Integer, default=120)
    burst_limit = Column(Integer, default=30)
    window_seconds = Column(Integer, default=60)
    is_active = Column(Boolean, default=True)
    demo_mode = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class DetectionTestResult(Base):
    __tablename__ = "detection_test_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    payload = Column(Text, nullable=False)
    test_type = Column(String(50), default="MANUAL_INSPECTION")
    detected_category = Column(String(50))
    matched_rule = Column(String(50))
    severity = Column(String(20))
    verdict = Column(String(20)) # BLOCKED, FLAGGED, ALLOWED
    confidence = Column(Float, default=0.0)
    execution_time_ms = Column(Float, default=0.0)
