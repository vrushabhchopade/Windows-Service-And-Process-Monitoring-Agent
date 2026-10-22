from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

# ----------------- Dashboard Schemas -----------------
class DashboardStats(BaseModel):
    total_requests: int
    malicious_requests: int
    blocked_requests: int
    critical_alerts: int
    unique_ips: int
    uptime_percentage: float = 99.98
    avg_latency_ms: float = 1.2
    malicious_rate_percent: float = 0.0
    block_efficiency_percent: float = 0.0

class TrafficDataPoint(BaseModel):
    time_label: str
    allowed_rps: float
    blocked_rps: float
    suspicious_rps: float
    total_rps: float

class AttackDistributionItem(BaseModel):
    category: str
    count: int
    percentage: float
    color: str

class TopMaliciousIP(BaseModel):
    ip_address: str
    country: str
    asn: str
    attacks_count: int
    reputation_score: int
    classification: str
    is_blocked: bool

# ----------------- Detection Schemas -----------------
class InspectRequest(BaseModel):
    payload: str = Field(..., description="The query parameter, URL path, header, or body text to inspect")
    source_ip: Optional[str] = Field("127.0.0.1", description="Client IP address")
    http_method: Optional[str] = Field("GET", description="HTTP request method")
    path: Optional[str] = Field("/api/v1/search", description="Request target URI")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Custom HTTP headers")

class InspectResponse(BaseModel):
    verdict: str                  # BLOCKED, FLAGGED, ALLOWED
    attack_category: str          # SQL Injection, Cross-Site Scripting, Directory Traversal, etc.
    matched_rule: str             # e.g., WAF-SQLI-001
    severity: str                 # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    confidence: float             # 0.0 to 1.0
    explanation: str              # Friendly explanation for beginners
    recommended_action: str       # SOC Playbook guidance
    normalized_payload: str       # Normalized string inspected
    execution_time_ms: float      # Engine processing latency
    is_attack: bool

class RuleRead(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    pattern: str
    description: str
    is_active: bool
    hits_count: int

# ----------------- Security Alerts Schemas -----------------
class AlertNoteCreate(BaseModel):
    author: str = "SOC Analyst"
    content: str

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    assignee: Optional[str] = None

class SecurityAlertRead(BaseModel):
    id: int
    alert_code: str
    timestamp: datetime
    title: str
    description: str
    category: str
    severity: str
    status: str
    target_endpoint: Optional[str]
    source_ip: Optional[str]
    unique_ip_count: int
    velocity_rps: float
    confidence_score: float
    assignee: str
    notes_json: str
    is_demo: bool

    model_config = ConfigDict(from_attributes=True)

# ----------------- Logs & Traffic Schemas -----------------
class HTTPLogRead(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    http_method: str
    path: str
    query_params: Optional[str]
    status_code: int
    latency_ms: float
    user_agent: str
    action: str
    threat_vector: str
    country_code: str
    asn_org: str
    is_demo: bool

    model_config = ConfigDict(from_attributes=True)

class SecurityEventRead(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    source_ip: str
    attack_category: str
    severity: str
    matched_rule_id: str
    matched_pattern: Optional[str]
    payload_snippet: Optional[str]
    action_taken: str
    confidence_score: float
    request_path: Optional[str]
    http_method: str
    user_agent: Optional[str]
    is_demo: bool

    model_config = ConfigDict(from_attributes=True)

# ----------------- IP Management Schemas -----------------
class BlockIPRequest(BaseModel):
    ip_address: str = Field(..., description="IPv4 or IPv6 address to block")
    reason: Optional[str] = Field("Malicious activity detected", description="Reason for blocking")

class IPReputationRead(BaseModel):
    id: int
    ip_address: str
    reputation_score: int
    classification: str
    country: str
    asn: str
    total_requests: int
    total_blocks: int
    is_blocked: bool
    block_reason: Optional[str]
    blocked_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)

# ----------------- Rate Limiting Schemas -----------------
class RateLimitConfigUpdate(BaseModel):
    requests_per_minute: int = Field(gt=0, le=10000)
    burst_limit: int = Field(gt=0, le=1000)
    window_seconds: int = Field(default=60, gt=0)
    is_active: bool = True
    demo_mode: bool = True

class RateLimitConfigRead(BaseModel):
    requests_per_minute: int
    burst_limit: int
    window_seconds: int
    is_active: bool
    demo_mode: bool
    current_tracked_ips: int = 0

# ----------------- WAF Rule Schemas -----------------
class WAFRuleCreate(BaseModel):
    rule_id: str
    name: str
    description: str
    category: str
    pattern: str
    severity: str = "HIGH"
    default_action: str = "BLOCK"
    is_active: bool = True

class WAFRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[str] = None
    default_action: Optional[str] = None
    is_active: Optional[bool] = None

# ----------------- Reports & System Health -----------------
class ReportSummary(BaseModel):
    report_generated_at: datetime
    reporting_window: str
    total_inspected_requests: int
    total_blocked_attacks: int
    top_attack_vectors: List[Dict[str, Any]]
    top_origin_countries: List[Dict[str, Any]]
    active_critical_alerts: int
    system_verdict: str

class HealthStatus(BaseModel):
    status: str
    version: str
    database: str
    timestamp: datetime
    environment: str
    uptime_seconds: float
    detection_engine: str
    rate_limiter: str
