import time
import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from app.utils.helpers import get_client_ip, sanitize_sensitive_data, get_mock_geo_asn
from app.detection.engine import inspect_request_data
from app.services.ratelimit_service import rate_limiter
from app.database import SessionLocal
from app.models.models import HTTPRequestLog, SecurityEvent, IPReputation

# Paths that are allowed to pass without blocking (for SOC testing, health, and docs)
EXEMPT_PREFIXES = (
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/detection/inspect", # Interactive attack test runner must inspect without throwing a 403
    "/api/health",
    "/favicon.ico"
)

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        client_ip = get_client_ip(request)
        path = request.url.path
        query = str(request.url.query)
        method = request.method

        # Check if route is exempt from inline blocking
        is_exempt = any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)

        # 1. IP Blocklist Check
        if not is_exempt:
            db = SessionLocal()
            try:
                ip_entry = db.query(IPReputation).filter(
                    IPReputation.ip_address == client_ip,
                    IPReputation.is_blocked == True
                ).first()
                if ip_entry:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "Access Denied by SentinelShield WAF",
                            "reason": f"Client IP {client_ip} is currently on the active edge blocklist.",
                            "block_reason": ip_entry.block_reason or "Malicious behavior detected",
                            "status_code": 403,
                            "client_ip": client_ip
                        }
                    )
            finally:
                db.close()

        # 2. Rate Limiting Check
        if not is_exempt:
            is_limited, retry_after, count = rate_limiter.is_rate_limited(client_ip)
            if is_limited:
                # Log 429 event
                db = SessionLocal()
                try:
                    geo = get_mock_geo_asn(client_ip)
                    req_log = HTTPRequestLog(
                        source_ip=client_ip,
                        http_method=method,
                        path=path,
                        query_params=sanitize_sensitive_data(query),
                        status_code=429,
                        latency_ms=1.1,
                        user_agent=request.headers.get("user-agent", "")[:500],
                        action="THROTTLED",
                        threat_vector="Rate Limit Exceeded",
                        country_code=geo["country"],
                        asn_org=geo["asn"],
                        is_demo=rate_limiter.demo_mode
                    )
                    db.add(req_log)
                    db.commit()
                except Exception:
                    db.rollback()
                finally:
                    db.close()

                response = JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "message": f"Rate limit threshold of {rate_limiter.requests_per_minute} req/min exceeded.",
                        "client_ip": client_ip,
                        "retry_after_seconds": retry_after,
                        "demo_mode": rate_limiter.demo_mode
                    }
                )
                response.headers["Retry-After"] = str(retry_after)
                return response

        # 3. Inline WAF Inspection on Query and Path
        if not is_exempt and query:
            inspection = inspect_request_data(
                payload=query,
                path=path,
                method=method,
                headers=dict(request.headers)
            )

            if inspection["is_attack"] and inspection["verdict"] == "BLOCKED":
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                geo = get_mock_geo_asn(client_ip)

                # Persist Security Event and Blocked HTTP Log
                db = SessionLocal()
                try:
                    event = SecurityEvent(
                        source_ip=client_ip,
                        attack_category=inspection["attack_category"],
                        severity=inspection["severity"],
                        matched_rule_id=inspection["matched_rule"],
                        matched_pattern=inspection["matched_rule"],
                        payload_snippet=sanitize_sensitive_data(query)[:500],
                        action_taken="BLOCKED",
                        confidence_score=inspection["confidence"],
                        request_path=path,
                        http_method=method,
                        user_agent=request.headers.get("user-agent", "")[:500],
                        is_demo=True
                    )
                    req_log = HTTPRequestLog(
                        source_ip=client_ip,
                        http_method=method,
                        path=path,
                        query_params=sanitize_sensitive_data(query),
                        status_code=403,
                        latency_ms=round(elapsed_ms, 2),
                        user_agent=request.headers.get("user-agent", "")[:500],
                        action="BLOCKED",
                        threat_vector=inspection["attack_category"],
                        country_code=geo["country"],
                        asn_org=geo["asn"],
                        is_demo=True
                    )
                    db.add(event)
                    db.add(req_log)
                    db.commit()
                except Exception:
                    db.rollback()
                finally:
                    db.close()

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request Blocked by SentinelShield WAF",
                        "attack_category": inspection["attack_category"],
                        "matched_rule": inspection["matched_rule"],
                        "severity": inspection["severity"],
                        "explanation": inspection["explanation"],
                        "recommendation": inspection["recommended_action"],
                        "client_ip": client_ip,
                        "verdict": "BLOCKED"
                    }
                )

        # 4. Process Request
        response: Response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Log clean API request (non-static) to database
        if path.startswith("/api/") and not path.startswith("/api/traffic") and not path.startswith("/api/dashboard"):
            try:
                db = SessionLocal()
                geo = get_mock_geo_asn(client_ip)
                log = HTTPRequestLog(
                    source_ip=client_ip,
                    http_method=method,
                    path=path,
                    query_params=sanitize_sensitive_data(query),
                    status_code=response.status_code,
                    latency_ms=round(elapsed_ms, 2),
                    user_agent=request.headers.get("user-agent", "")[:500],
                    action="ALLOWED" if response.status_code < 400 else "BLOCKED",
                    threat_vector="CLEAN",
                    country_code=geo["country"],
                    asn_org=geo["asn"],
                    is_demo=True
                )
                db.add(log)
                db.commit()
                db.close()
            except Exception:
                pass

        return response
