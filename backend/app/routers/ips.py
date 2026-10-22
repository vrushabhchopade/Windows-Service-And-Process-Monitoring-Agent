from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import IPReputation
from app.schemas.schemas import IPReputationRead, BlockIPRequest
from app.utils.helpers import get_mock_geo_asn

router = APIRouter(prefix="/ips", tags=["IP Management & Threat Intelligence"])

@router.get("", response_model=List[IPReputationRead])
def list_ips(
    blocked_only: bool = Query(False, description="Filter for blocked IPs only"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Lists IP reputation records and active edge blocks."""
    query = db.query(IPReputation)
    if blocked_only:
        query = query.filter(IPReputation.is_blocked == True)

    return query.order_by(IPReputation.total_blocks.desc(), IPReputation.reputation_score.desc()).limit(limit).all()

@router.get("/{ip_address}", response_model=IPReputationRead)
def get_ip(ip_address: str, db: Session = Depends(get_db)):
    """Fetches threat intelligence classification for an IP address."""
    entry = db.query(IPReputation).filter(IPReputation.ip_address == ip_address).first()
    if not entry:
        geo = get_mock_geo_asn(ip_address)
        entry = IPReputation(
            ip_address=ip_address,
            reputation_score=15,
            classification=geo["classification"],
            country=geo["country"],
            asn=geo["asn"],
            total_requests=1,
            total_blocks=0,
            is_blocked=False
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
    return entry

@router.post("/blocklist", response_model=IPReputationRead)
def block_ip(payload: BlockIPRequest, db: Session = Depends(get_db)):
    """Adds an IP address to the active edge firewall drop list."""
    entry = db.query(IPReputation).filter(IPReputation.ip_address == payload.ip_address).first()
    geo = get_mock_geo_asn(payload.ip_address)

    if not entry:
        entry = IPReputation(
            ip_address=payload.ip_address,
            reputation_score=95,
            classification="MALICIOUS",
            country=geo["country"],
            asn=geo["asn"],
            total_requests=1,
            total_blocks=1,
            is_blocked=True,
            block_reason=payload.reason or "Manual SOC Blocklist Deployment",
            blocked_at=datetime.utcnow()
        )
        db.add(entry)
    else:
        entry.is_blocked = True
        entry.block_reason = payload.reason or "Manual SOC Blocklist Deployment"
        entry.blocked_at = datetime.utcnow()
        entry.reputation_score = max(entry.reputation_score, 90)

    db.commit()
    db.refresh(entry)
    return entry

@router.delete("/blocklist/{ip_address}")
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    """Removes an IP address from the active edge blocklist."""
    entry = db.query(IPReputation).filter(IPReputation.ip_address == ip_address).first()
    if not entry or not entry.is_blocked:
        return {"message": f"IP {ip_address} is not currently blocked.", "ip": ip_address, "is_blocked": False}

    entry.is_blocked = False
    entry.block_reason = "Unblocked by SOC Analyst"
    db.commit()
    return {"message": f"IP {ip_address} successfully unblocked and removed from edge firewall.", "ip": ip_address, "is_blocked": False}
