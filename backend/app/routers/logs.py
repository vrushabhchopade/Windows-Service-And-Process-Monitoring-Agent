from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import SecurityEvent
from app.schemas.schemas import SecurityEventRead

router = APIRouter(prefix="/logs", tags=["Security Audit Logs"])

@router.get("", response_model=List[SecurityEventRead])
def list_logs(
    search: Optional[str] = Query(None, description="Search by IP, payload, or rule"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    category: Optional[str] = Query(None, description="Attack category filter"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieves full security event audit trail logs."""
    query = db.query(SecurityEvent)

    if severity and severity.upper() != "ALL":
        query = query.filter(SecurityEvent.severity == severity.upper())
    if category and category.upper() != "ALL":
        query = query.filter(SecurityEvent.attack_category.ilike(f"%{category}%"))
    if search:
        s = f"%{search}%"
        query = query.filter(
            (SecurityEvent.source_ip.ilike(s)) |
            (SecurityEvent.payload_snippet.ilike(s)) |
            (SecurityEvent.matched_rule_id.ilike(s))
        )

    return query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/{log_id}", response_model=SecurityEventRead)
def get_log_detail(log_id: int, db: Session = Depends(get_db)):
    """Fetches full log trace context for deep packet inspection."""
    log = db.query(SecurityEvent).filter(SecurityEvent.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Log record #{log_id} not found.")
    return log
