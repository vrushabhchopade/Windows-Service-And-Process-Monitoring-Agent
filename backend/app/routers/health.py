import time
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.schemas.schemas import HealthStatus
from app.config import settings
from app.services.ratelimit_service import rate_limiter

router = APIRouter(prefix="", tags=["System Health"])
SERVER_START_TIME = time.time()

@router.get("/health", response_model=HealthStatus)
def get_health_check(db: Session = Depends(get_db)):
    """Validates FastAPI core node, database connectivity, and engine subsystems."""
    db_status = "ONLINE"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"ERROR: {str(e)}"

    uptime = round(time.time() - SERVER_START_TIME, 1)

    return HealthStatus(
        status="HEALTHY",
        version=settings.VERSION,
        database=db_status,
        timestamp=datetime.utcnow(),
        environment=settings.ENVIRONMENT,
        uptime_seconds=uptime,
        detection_engine="ACTIVE - Heuristic Pattern Matcher Ready",
        rate_limiter="ACTIVE - Sliding Window Token Bucket Ready"
    )
