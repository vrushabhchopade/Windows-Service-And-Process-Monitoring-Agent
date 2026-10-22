import pytest
from app.services.ratelimit_service import RateLimiter

def test_rate_limiter_allow():
    limiter = RateLimiter()
    limiter.update_config(rpm=5, burst=5, window=60, active=True, demo=True)
    ip = "203.0.113.199"

    for _ in range(5):
        blocked, retry, count = limiter.is_rate_limited(ip)
        assert blocked is False

def test_rate_limiter_block():
    limiter = RateLimiter()
    limiter.update_config(rpm=3, burst=3, window=60, active=True, demo=True)
    ip = "198.51.100.88"

    # Consume allowance
    for _ in range(3):
        limiter.is_rate_limited(ip)

    # 4th request must be blocked
    blocked, retry, count = limiter.is_rate_limited(ip)
    assert blocked is True
    assert retry > 0

def test_rate_limiter_inactive():
    limiter = RateLimiter()
    limiter.update_config(rpm=1, burst=1, window=60, active=False, demo=True)
    ip = "192.0.2.1"

    for _ in range(5):
        blocked, retry, count = limiter.is_rate_limited(ip)
        assert blocked is False
