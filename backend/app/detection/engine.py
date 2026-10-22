import re
import time
import urllib.parse
from typing import Dict, Any, Optional
from app.detection.rules import RULES

# Precompile regex rules for maximum throughput
COMPILED_RULES = []
for r in RULES:
    try:
        compiled = re.compile(r["pattern"])
        rule_copy = dict(r)
        rule_copy["_compiled"] = compiled
        COMPILED_RULES.append(rule_copy)
    except re.error as e:
        print(f"Warning: Failed to compile rule {r.get('rule_id')}: {e}")

# Whitelist patterns for common benign inputs to avoid false positives
BENIGN_PATTERNS = [
    re.compile(r"^[a-zA-Z0-9_\-\.\s]{1,100}$"),               # Simple alphanumeric and punctuation
    re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"), # Email addresses
    re.compile(r"^[0-9a-fA-F\-]{36}$"),                       # Standard UUIDs
]

def normalize_input(raw: str) -> str:
    """
    Safely normalizes incoming input before inspection:
    - Recursively decodes URL-encoded entities (handles double/triple encoding, e.g. %2527 -> %27 -> ')
    - Replaces null bytes
    - Normalizes multiple whitespace characters
    """
    if not raw or not isinstance(raw, str):
        return ""
    
    current = raw
    # Safely decode up to 3 passes to unwrap nested encoding
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        except Exception:
            break

    # Strip harmful null characters safely
    normalized = current.replace("\x00", "").strip()
    return normalized

def is_benign(normalized: str) -> bool:
    """Checks if the normalized payload clearly matches a benign innocent format."""
    if not normalized:
        return True
    
    # Very short alphanumeric or safe single words
    if len(normalized) <= 3 and normalized.isalnum():
        return True
        
    for bp in BENIGN_PATTERNS:
        if bp.match(normalized):
            return True
            
    return False

def inspect_request_data(
    payload: str,
    path: str = "",
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Inspects URL path, query params, headers, and payload.
    Does NOT execute any commands or payloads.
    Returns detection results, category, severity, verdict, and explanation.
    """
    start_time = time.perf_counter()
    headers = headers or {}
    
    # Combine relevant sources for comprehensive inspection
    user_agent = headers.get("user-agent", "") or headers.get("User-Agent", "")
    full_inspection_buffer = f"{path} {payload} {user_agent}"
    
    normalized = normalize_input(payload)
    normalized_full = normalize_input(full_inspection_buffer)
    
    # Check if inspection buffer is benign and contains no attack indicators
    # Note: If payload or headers contain quotes, tags, operators, or scanner keywords, inspect thoroughly
    has_suspicious_characters = any(c in normalized_full.lower() for c in (
        "'", "\"", "<", ">", ";", "|", "`", "../", "..\\", "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster"
    ))

    if not has_suspicious_characters and is_benign(normalized):
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return {
            "is_attack": False,
            "verdict": "ALLOWED",
            "attack_category": "Benign Traffic",
            "matched_rule": "NONE",
            "severity": "SAFE",
            "confidence": 1.0,
            "explanation": "No malicious signatures, injection patterns, or anomalous sequences detected.",
            "recommended_action": "Allow request through to application origin.",
            "normalized_payload": normalized,
            "execution_time_ms": round(elapsed_ms, 3)
        }

    # Evaluate against compiled rules
    for rule in COMPILED_RULES:
        # Check against normalized full string and raw full string
        match = rule["_compiled"].search(normalized_full) or rule["_compiled"].search(full_inspection_buffer)
        if match:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            verdict = "BLOCKED" if rule.get("default_action") == "BLOCK" else "FLAGGED"
            
            return {
                "is_attack": True,
                "verdict": verdict,
                "attack_category": rule["category"],
                "matched_rule": rule["rule_id"],
                "severity": rule["severity"],
                "confidence": rule.get("confidence", 0.95),
                "explanation": rule["explanation"],
                "recommended_action": rule["recommendation"],
                "normalized_payload": normalized[:250],
                "execution_time_ms": round(elapsed_ms, 3)
            }

    # If no rule matched
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return {
        "is_attack": False,
        "verdict": "ALLOWED",
        "attack_category": "Clean / Legitimate",
        "matched_rule": "NONE",
        "severity": "SAFE",
        "confidence": 0.98,
        "explanation": "Request payload passed heuristic signature validation without triggering any active WAF rule.",
        "recommended_action": "Forward traffic to upstream API gateway.",
        "normalized_payload": normalized[:250],
        "execution_time_ms": round(elapsed_ms, 3)
    }
