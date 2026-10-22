from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import HTTPRequestLog
from app.schemas.schemas import HTTPLogRead

router = APIRouter(prefix="/traffic", tags=["Traffic Telemetry"])

@router.get("", response_model=List[HTTPLogRead])
def get_traffic_logs(
    method: Optional[str] = Query(None, description="Filter by HTTP method (GET, POST, etc.)"),
    status_code: Optional[int] = Query(None, description="Filter by HTTP response code"),
    action: Optional[str] = Query(None, description="Filter by action (ALLOWED, BLOCKED, THROTTLED)"),
    search: Optional[str] = Query(None, description="Search query against path or source IP"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Returns the live stream of inspected HTTP traffic frames."""
    query = db.query(HTTPRequestLog)

    if method and method.upper() != "ALL":
        query = query.filter(HTTPRequestLog.http_method == method.upper())
    if status_code and status_code != 0:
        query = query.filter(HTTPRequestLog.status_code == status_code)
    if action and action.upper() != "ALL":
        query = query.filter(HTTPRequestLog.action == action.upper())
    if search:
        s = f"%{search}%"
        query = query.filter((HTTPRequestLog.path.ilike(s)) | (HTTPRequestLog.source_ip.ilike(s)))

    logs = query.order_by(HTTPRequestLog.timestamp.desc()).offset(offset).limit(limit).all()
    return logs

@router.get("/{event_id}", response_model=HTTPLogRead)
def get_traffic_event(event_id: int, db: Session = Depends(get_db)):
    """Fetches details for an individual inspected HTTP transaction."""
    log = db.query(HTTPRequestLog).filter(HTTPRequestLog.id == event_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Traffic event with ID {event_id} not found.")
    return log
