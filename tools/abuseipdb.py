"""
AbuseIPDB Tool
==============
Queries AbuseIPDB to check if an IP address has been reported
for malicious activity (scanning, brute force, DDoS, etc.).

Free tier: 1,000 checks/day.
"""

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, ABUSEIPDB_RATE_LIMIT
from models import AbuseIPDBResult
from utils.rate_limiter import rate_limiter


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def lookup_ip(ip: str) -> AbuseIPDBResult:
    """
    Check an IP address against AbuseIPDB.

    Returns abuse confidence score (0-100), number of reports,
    ISP info, country, and whether it's a known Tor exit node.

    Note: private/internal IPs (like 10.0.1.50) return null for
    fields like country/ISP, so we coerce None -> "" with `or ""`.
    """
    rate_limiter.wait_if_needed("abuseipdb", ABUSEIPDB_RATE_LIMIT)

    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,  # Look back 90 days
                "verbose": "",
            },
            timeout=15,
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            # `or ""` / `or 0` coerces null values (private IPs) to safe defaults
            return AbuseIPDBResult(
                ip_address=ip,
                abuse_confidence_score=data.get("abuseConfidenceScore") or 0,
                total_reports=data.get("totalReports") or 0,
                country_code=data.get("countryCode") or "",
                isp=data.get("isp") or "",
                domain=data.get("domain") or "",
                is_tor=data.get("isTor") or False,
                is_whitelisted=data.get("isWhitelisted") or False,
                last_reported_at=data.get("lastReportedAt"),
            )
        elif resp.status_code == 429:
            return AbuseIPDBResult(ip_address=ip, error="Rate limit exceeded")
        elif resp.status_code == 422:
            return AbuseIPDBResult(ip_address=ip, error="Invalid IP address format")
        else:
            return AbuseIPDBResult(ip_address=ip, error=f"HTTP {resp.status_code}")

    except requests.RequestException as e:
        return AbuseIPDBResult(ip_address=ip, error=str(e))


# -- Quick test --
if __name__ == "__main__":
    print("Testing AbuseIPDB lookup...")
    print("=" * 50)

    result = lookup_ip("8.8.8.8")
    if result.error:
        print(f"  Error: {result.error}")
    else:
        print(f"  IP: {result.ip_address}")
        print(f"  Abuse Score: {result.abuse_confidence_score}/100")
        print(f"  Reports: {result.total_reports}")
        print(f"  Country: {result.country_code}")
        print(f"  ISP: {result.isp}")
        print(f"  Tor Node: {result.is_tor}")

    print("\nTesting private IP (10.0.1.50)...")
    result2 = lookup_ip("10.0.1.50")
    if result2.error:
        print(f"  Error: {result2.error}")
    else:
        print(f"  IP: {result2.ip_address}")
        print(f"  Abuse Score: {result2.abuse_confidence_score}/100")
        print(f"  Country: '{result2.country_code}' (empty is expected for private IP)")

    print("\nDone.")
