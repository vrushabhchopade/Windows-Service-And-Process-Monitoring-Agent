import time
from collections import defaultdict
from typing import Dict, List, Tuple
from app.config import settings

class RateLimiter:
    """
    In-memory Sliding Window Rate Limiter for SentinelShield.
    Tracks timestamps of requests per client IP address.
    """
    def __init__(self):
        # ip -> list of float timestamps
        self.request_history: Dict[str, List[float]] = defaultdict(list)
        self.requests_per_minute: int = settings.DEFAULT_RATE_LIMIT
        self.burst_limit: int = 30
        self.window_seconds: int = settings.RATE_LIMIT_WINDOW_SECONDS
        self.is_active: bool = True
        self.demo_mode: bool = settings.DEMO_MODE

    def update_config(self, rpm: int, burst: int, window: int, active: bool, demo: bool):
        self.requests_per_minute = rpm
        self.burst_limit = burst
        self.window_seconds = window
        self.is_active = active
        self.demo_mode = demo

    def get_config(self) -> Dict:
        return {
            "requests_per_minute": self.requests_per_minute,
            "burst_limit": self.burst_limit,
            "window_seconds": self.window_seconds,
            "is_active": self.is_active,
            "demo_mode": self.demo_mode,
            "current_tracked_ips": len(self.request_history)
        }

    def is_rate_limited(self, ip_address: str) -> Tuple[bool, int, int]:
        """
        Evaluates whether an IP address has exceeded the rate limit.
        Returns:
            (is_blocked: bool, retry_after_seconds: int, current_count: int)
        """
        if not self.is_active:
            return False, 0, 0

        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean up timestamps older than the sliding window
        timestamps = [ts for ts in self.request_history[ip_address] if ts > window_start]
        self.request_history[ip_address] = timestamps

        current_count = len(timestamps)

        # Check threshold
        limit = self.requests_per_minute
        if current_count >= limit:
            oldest_relevant = timestamps[0]
            retry_after = max(1, int(oldest_relevant + self.window_seconds - now))
            return True, retry_after, current_count

        # Record this request timestamp
        self.request_history[ip_address].append(now)
        return False, 0, current_count + 1

    def clear(self):
        self.request_history.clear()

# Global singleton rate limiter instance
rate_limiter = RateLimiter()
