from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import RateLimitConfiguration
from app.schemas.schemas import RateLimitConfigRead, RateLimitConfigUpdate
from app.services.ratelimit_service import rate_limiter

router = APIRouter(prefix="/rate-limits", tags=["Rate Limiting Policy"])

@router.get("", response_model=RateLimitConfigRead)
def get_rate_limits(db: Session = Depends(get_db)):
    """Retrieves current edge rate limiting policy and active thresholds."""
    config = rate_limiter.get_config()
    return RateLimitConfigRead(**config)

@router.put("", response_model=RateLimitConfigRead)
def update_rate_limits(payload: RateLimitConfigUpdate, db: Session = Depends(get_db)):
    """Updates edge rate limiting policy dynamically without restarting the server."""
    rate_limiter.update_config(
        rpm=payload.requests_per_minute,
        burst=payload.burst_limit,
        window=payload.window_seconds,
        active=payload.is_active,
        demo=payload.demo_mode
    )

    # Persist in DB
    db_config = db.query(RateLimitConfiguration).first()
    if not db_config:
        db_config = RateLimitConfiguration(
            requests_per_minute=payload.requests_per_minute,
            burst_limit=payload.burst_limit,
            window_seconds=payload.window_seconds,
            is_active=payload.is_active,
            demo_mode=payload.demo_mode
        )
        db.add(db_config)
    else:
        db_config.requests_per_minute = payload.requests_per_minute
        db_config.burst_limit = payload.burst_limit
        db_config.window_seconds = payload.window_seconds
        db_config.is_active = payload.is_active
        db_config.demo_mode = payload.demo_mode

    db.commit()
    config = rate_limiter.get_config()
    return RateLimitConfigRead(**config)
