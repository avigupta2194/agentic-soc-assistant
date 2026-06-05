"""
Rate limiter utility for API calls.
Prevents hitting free tier limits on VirusTotal, AbuseIPDB, etc.
Uses a simple token bucket approach.
"""

import time
from collections import defaultdict


class RateLimiter:
    """
    Simple rate limiter that tracks calls per service
    and sleeps if we're about to exceed the limit.
    """

    def __init__(self):
        self._call_timestamps: dict[str, list[float]] = defaultdict(list)

    def wait_if_needed(self, service: str, max_per_minute: int) -> None:
        """
        Block until it's safe to make another call to the given service.

        Args:
            service: Name of the API service (e.g., 'virustotal')
            max_per_minute: Maximum allowed requests per minute
        """
        now = time.time()
        window_start = now - 60.0

        # Clean old timestamps outside the 1-minute window
        self._call_timestamps[service] = [
            ts for ts in self._call_timestamps[service]
            if ts > window_start
        ]

        # If we've hit the limit, sleep until the oldest call exits the window
        if len(self._call_timestamps[service]) >= max_per_minute:
            oldest = self._call_timestamps[service][0]
            sleep_time = 60.0 - (now - oldest) + 0.5  # +0.5s buffer
            if sleep_time > 0:
                print(f"  ⏳ Rate limit reached for {service}. "
                      f"Waiting {sleep_time:.1f}s...")
                time.sleep(sleep_time)

        # Record this call
        self._call_timestamps[service].append(time.time())


# Global singleton — import this in tool modules
rate_limiter = RateLimiter()
