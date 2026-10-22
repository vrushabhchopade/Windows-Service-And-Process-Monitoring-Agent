from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.database import get_db
from app.models.models import SecurityEvent, DetectionTestResult, HTTPRequestLog
from app.schemas.schemas import InspectRequest, InspectResponse, SecurityEventRead, RuleRead
from app.detection.engine import inspect_request_data
from app.detection.rules import RULES
from app.utils.helpers import get_mock_geo_asn

router = APIRouter(prefix="/detection", tags=["Detection & Inspection"])

@router.post("/inspect", response_model=InspectResponse)
def inspect_payload_endpoint(req: InspectRequest, db: Session = Depends(get_db)):
    """
    Evaluates a user-supplied payload against WAF & IDS detection rules.
    Provides immediate severity, matched rule, and SOC playbook remediation.
    Safe: Does NOT execute shell commands or database payloads.
    """
    result = inspect_request_data(
        payload=req.payload,
        path=req.path or "/api/v1/search",
        method=req.http_method or "GET",
        headers=req.headers or {}
    )

    # Persist the test execution record
    test_record = DetectionTestResult(
        payload=req.payload[:1000],
        test_type="MANUAL_INSPECTION",
        detected_category=result["attack_category"],
        matched_rule=result["matched_rule"],
        severity=result["severity"],
        verdict=result["verdict"],
        confidence=result["confidence"],
        execution_time_ms=result["execution_time_ms"]
    )
    db.add(test_record)

    # If an attack was flagged or blocked, also append a SecurityEvent so live dashboards immediately reflect it
    if result["is_attack"]:
        geo = get_mock_geo_asn(req.source_ip or "127.0.0.1")
        sec_event = SecurityEvent(
            source_ip=req.source_ip or "127.0.0.1",
            attack_category=result["attack_category"],
            severity=result["severity"],
            matched_rule_id=result["matched_rule"],
            matched_pattern=result["matched_rule"],
            payload_snippet=req.payload[:500],
            action_taken=result["verdict"],
            confidence_score=result["confidence"],
            request_path=req.path or "/api/v1/search",
            http_method=req.http_method or "GET",
            user_agent="Interactive Threat Console / Tester",
            is_demo=True
        )
        http_log = HTTPRequestLog(
            source_ip=req.source_ip or "127.0.0.1",
            http_method=req.http_method or "GET",
            path=req.path or "/api/v1/search",
            query_params=req.payload[:500],
            status_code=403 if result["verdict"] == "BLOCKED" else 200,
            latency_ms=result["execution_time_ms"],
            user_agent="Interactive Threat Console / Tester",
            action=result["verdict"],
            threat_vector=result["attack_category"],
            country_code=geo["country"],
            asn_org=geo["asn"],
            is_demo=True
        )
        db.add(sec_event)
        db.add(http_log)

    db.commit()

    return InspectResponse(
        verdict=result["verdict"],
        attack_category=result["attack_category"],
        matched_rule=result["matched_rule"],
        severity=result["severity"],
        confidence=result["confidence"],
        explanation=result["explanation"],
        recommended_action=result["recommended_action"],
        normalized_payload=result["normalized_payload"],
        execution_time_ms=result["execution_time_ms"],
        is_attack=result["is_attack"]
    )

@router.get("/events", response_model=List[SecurityEventRead])
def get_security_events(
    category: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists security events and attack alerts stored in the database."""
    query = db.query(SecurityEvent)
    if category and category.upper() != "ALL":
        query = query.filter(SecurityEvent.attack_category.ilike(f"%{category}%"))
    if severity and severity.upper() != "ALL":
        query = query.filter(SecurityEvent.severity == severity.upper())

    return query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/rules", response_model=List[RuleRead])
def get_detection_rules():
    """Lists all built-in active WAF and IDS detection rules."""
    rules_out = []
    for r in RULES:
        rules_out.append(
            RuleRead(
                rule_id=r["rule_id"],
                name=r["name"],
                category=r["category"],
                severity=r["severity"],
                pattern=r["pattern"],
                description=r["description"],
                is_active=True,
                hits_count=142
            )
        )
    return rules_out
