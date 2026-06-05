"""
VirusTotal Tool
===============
Queries the VirusTotal API to check if an IOC (IP, domain, URL, or file hash)
has been flagged as malicious by security vendors.

Free tier: 4 requests/minute, 500/day.
"""

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL, VIRUSTOTAL_RATE_LIMIT
from models import IOC, IOCType, VirusTotalResult
from utils.rate_limiter import rate_limiter


def _get_headers() -> dict:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def _parse_analysis_stats(data: dict) -> dict:
    """Extract last_analysis_stats from a VT response."""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": sum(stats.values()) if stats else 0,
        "reputation": attributes.get("reputation", 0),
        "tags": attributes.get("tags", []),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def lookup_ip(ip: str) -> VirusTotalResult:
    """Look up an IP address on VirusTotal."""
    rate_limiter.wait_if_needed("virustotal", VIRUSTOTAL_RATE_LIMIT)

    try:
        resp = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=_get_headers(),
            timeout=15,
        )

        if resp.status_code == 200:
            parsed = _parse_analysis_stats(resp.json())
            return VirusTotalResult(
                ioc_value=ip,
                malicious_count=parsed["malicious"],
                suspicious_count=parsed["suspicious"],
                harmless_count=parsed["harmless"],
                total_engines=parsed["total"],
                reputation_score=parsed["reputation"],
                tags=parsed["tags"],
                last_analysis_date=str(parsed["last_analysis_date"]) if parsed["last_analysis_date"] else None,
            )
        elif resp.status_code == 404:
            return VirusTotalResult(ioc_value=ip, error="Not found in VirusTotal database")
        elif resp.status_code == 429:
            return VirusTotalResult(ioc_value=ip, error="Rate limit exceeded")
        else:
            return VirusTotalResult(ioc_value=ip, error=f"HTTP {resp.status_code}")

    except requests.RequestException as e:
        return VirusTotalResult(ioc_value=ip, error=str(e))


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def lookup_domain(domain: str) -> VirusTotalResult:
    """Look up a domain on VirusTotal."""
    rate_limiter.wait_if_needed("virustotal", VIRUSTOTAL_RATE_LIMIT)

    try:
        resp = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=_get_headers(),
            timeout=15,
        )

        if resp.status_code == 200:
            parsed = _parse_analysis_stats(resp.json())
            return VirusTotalResult(
                ioc_value=domain,
                malicious_count=parsed["malicious"],
                suspicious_count=parsed["suspicious"],
                harmless_count=parsed["harmless"],
                total_engines=parsed["total"],
                reputation_score=parsed["reputation"],
                tags=parsed["tags"],
                last_analysis_date=str(parsed["last_analysis_date"]) if parsed["last_analysis_date"] else None,
            )
        elif resp.status_code == 404:
            return VirusTotalResult(ioc_value=domain, error="Not found in VirusTotal database")
        else:
            return VirusTotalResult(ioc_value=domain, error=f"HTTP {resp.status_code}")

    except requests.RequestException as e:
        return VirusTotalResult(ioc_value=domain, error=str(e))


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def lookup_hash(file_hash: str) -> VirusTotalResult:
    """Look up a file hash (MD5, SHA1, SHA256) on VirusTotal."""
    rate_limiter.wait_if_needed("virustotal", VIRUSTOTAL_RATE_LIMIT)

    try:
        resp = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
            headers=_get_headers(),
            timeout=15,
        )

        if resp.status_code == 200:
            parsed = _parse_analysis_stats(resp.json())
            return VirusTotalResult(
                ioc_value=file_hash,
                malicious_count=parsed["malicious"],
                suspicious_count=parsed["suspicious"],
                harmless_count=parsed["harmless"],
                total_engines=parsed["total"],
                reputation_score=parsed["reputation"],
                tags=parsed["tags"],
                last_analysis_date=str(parsed["last_analysis_date"]) if parsed["last_analysis_date"] else None,
            )
        elif resp.status_code == 404:
            return VirusTotalResult(ioc_value=file_hash, error="Not found in VirusTotal database")
        else:
            return VirusTotalResult(ioc_value=file_hash, error=f"HTTP {resp.status_code}")

    except requests.RequestException as e:
        return VirusTotalResult(ioc_value=file_hash, error=str(e))


def lookup_ioc(ioc: IOC) -> VirusTotalResult:
    """
    Route an IOC to the correct VirusTotal lookup method.
    This is what the agent calls — it doesn't need to know
    which endpoint to hit, just passes the IOC.
    """
    if ioc.ioc_type == IOCType.IP:
        return lookup_ip(ioc.value)
    elif ioc.ioc_type == IOCType.DOMAIN:
        return lookup_domain(ioc.value)
    elif ioc.ioc_type in (IOCType.HASH_SHA256, IOCType.HASH_MD5, IOCType.HASH_SHA1):
        return lookup_hash(ioc.value)
    elif ioc.ioc_type == IOCType.URL:
        # For URLs, extract and look up the domain
        import re
        domain_match = re.search(r"https?://([^/:]+)", ioc.value)
        if domain_match:
            return lookup_domain(domain_match.group(1))
        return VirusTotalResult(ioc_value=ioc.value, error="Could not extract domain from URL")
    else:
        return VirusTotalResult(ioc_value=ioc.value, error=f"Unsupported IOC type: {ioc.ioc_type}")


# ── Quick test ────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing VirusTotal lookups...")
    print("=" * 50)

    # Test with a known safe IP (Google DNS)
    test_ip = IOC(value="8.8.8.8", ioc_type=IOCType.IP)
    result = lookup_ioc(test_ip)

    if result.error:
        print(f"  Error: {result.error}")
    else:
        print(f"  IP: {result.ioc_value}")
        print(f"  Malicious: {result.malicious_count}/{result.total_engines}")
        print(f"  Suspicious: {result.suspicious_count}")
        print(f"  Reputation: {result.reputation_score}")

    print("\nDone.")
