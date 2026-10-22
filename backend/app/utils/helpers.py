from fastapi import Request
from app.config import settings

def get_client_ip(request: Request) -> str:
    """
    Safely extracts client IP address.
    Never blindly trusts X-Forwarded-For unless the direct peer is an explicitly trusted proxy.
    """
    direct_ip = request.client.host if request.client else "127.0.0.1"

    if direct_ip in settings.TRUSTED_PROXIES:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First IP in the list is the original client IP
            client_ip = forwarded_for.split(",")[0].strip()
            return client_ip

    return direct_ip

def sanitize_sensitive_data(text: str) -> str:
    """
    Redacts passwords, bearer tokens, and secrets from request logs.
    """
    if not text:
        return ""
    import re
    redacted = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key|auth|authorization)=([^&;\s]+)",
        r"\1=[REDACTED]",
        text
    )
    redacted = re.sub(
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
        "Bearer [REDACTED_TOKEN]",
        redacted
    )
    return redacted

def get_mock_geo_asn(ip: str) -> dict:
    """Provides realistic geolocation and ASN metadata for demonstration."""
    if ip.startswith("185.220.") or ip.startswith("194.135.") or ip.startswith("194.26."):
        return {"country": "DE", "asn": "AS197019 TOR-RELAY-EXIT", "classification": "TOR_EXIT_NODE"}
    elif ip.startswith("91.240.") or ip.startswith("185.191."):
        return {"country": "NL", "asn": "AS14061 DIGITALOCEAN-MESH", "classification": "PROXY"}
    elif ip.startswith("66.249.") or ip.startswith("172.56."):
        return {"country": "US", "asn": "AS15169 GOOGLE-EDGE", "classification": "CLEAN"}
    elif ip.startswith("127.0.") or ip == "::1":
        return {"country": "LOCAL", "asn": "AS0 LOCALHOST-NODE", "classification": "CLEAN"}
    else:
        return {"country": "US", "asn": "AS16509 AWS-GLOBAL-INGRESS", "classification": "SUSPICIOUS"}
