"""
Geolocation Tool
================
Uses ip-api.com to get geographic location of an IP address.
Completely free, no API key required.

Free tier: 45 requests/minute.
"""

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from config import IP_API_BASE_URL, IP_API_RATE_LIMIT
from models import GeoLocation
from utils.rate_limiter import rate_limiter


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def lookup_ip(ip: str) -> GeoLocation:
    """
    Get geolocation data for an IP address.

    Returns country, region, city, coordinates, ISP, and organization.
    """
    rate_limiter.wait_if_needed("ip_api", IP_API_RATE_LIMIT)

    try:
        resp = requests.get(
            f"{IP_API_BASE_URL}/{ip}",
            params={"fields": "status,message,country,regionName,city,lat,lon,isp,org"},
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()

            if data.get("status") == "success":
                return GeoLocation(
                    ip_address=ip,
                    country=data.get("country", ""),
                    region=data.get("regionName", ""),
                    city=data.get("city", ""),
                    lat=data.get("lat", 0.0),
                    lon=data.get("lon", 0.0),
                    isp=data.get("isp", ""),
                    org=data.get("org", ""),
                )
            else:
                return GeoLocation(
                    ip_address=ip,
                    error=data.get("message", "Lookup failed"),
                )
        else:
            return GeoLocation(ip_address=ip, error=f"HTTP {resp.status_code}")

    except requests.RequestException as e:
        return GeoLocation(ip_address=ip, error=str(e))


# ── Quick test ────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing Geolocation lookup...")
    print("=" * 50)

    result = lookup_ip("8.8.8.8")

    if result.error:
        print(f"  Error: {result.error}")
    else:
        print(f"  IP: {result.ip_address}")
        print(f"  Location: {result.city}, {result.region}, {result.country}")
        print(f"  Coordinates: {result.lat}, {result.lon}")
        print(f"  ISP: {result.isp}")
        print(f"  Org: {result.org}")

    print("\nDone.")
