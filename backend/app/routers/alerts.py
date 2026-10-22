import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import SecurityAlert
from app.schemas.schemas import SecurityAlertRead, AlertStatusUpdate, AlertNoteCreate

router = APIRouter(prefix="/alerts", tags=["Security Alerts & Incident Response"])

@router.get("", response_model=List[SecurityAlertRead])
def list_alerts(
    status: Optional[str] = Query(None, description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Lists security alerts monitored in the incident queue."""
    query = db.query(SecurityAlert)
    if status and status.upper() != "ALL":
        query = query.filter(SecurityAlert.status == status.upper())
    if severity and severity.upper() != "ALL":
        query = query.filter(SecurityAlert.severity == severity.upper())

    return query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()

@router.get("/{alert_id}", response_model=SecurityAlertRead)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Fetches full alert dossier and heuristic telemetry."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found.")
    return alert

@router.patch("/{alert_id}", response_model=SecurityAlertRead)
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    """Updates an incident's triage status or assigns it to an on-duty analyst."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found.")

    alert.status = payload.status.upper()
    if payload.assignee:
        alert.assignee = payload.assignee

    # Automatically log a status transition note
    try:
        notes = json.loads(alert.notes_json or "[]")
    except Exception:
        notes = []

    notes.append({
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "author": "SOC Triage Workflow",
        "content": f"Status updated to '{payload.status.upper()}'" + (f" and assigned to {payload.assignee}" if payload.assignee else ".")
    })
    alert.notes_json = json.dumps(notes)

    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/notes", response_model=SecurityAlertRead)
def add_alert_note(alert_id: int, note_data: AlertNoteCreate, db: Session = Depends(get_db)):
    """Appends an analyst forensic note to the alert timeline."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found.")

    try:
        notes = json.loads(alert.notes_json or "[]")
    except Exception:
        notes = []

    notes.append({
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "author": note_data.author or "SOC Analyst",
        "content": note_data.content
    })
    alert.notes_json = json.dumps(notes)

    db.commit()
    db.refresh(alert)
    return alert
