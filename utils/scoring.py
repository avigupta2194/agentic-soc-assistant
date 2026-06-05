"""
Threat Scoring
==============
Computes a 0-100 threat score for an IOC by combining signals
from VirusTotal, AbuseIPDB, and geolocation.

This is deterministic (rule-based) scoring — NOT the LLM.
We want the score to be explainable and consistent. The LLM
handles narrative analysis; this handles the numbers.
"""

from models import EnrichmentResult


def compute_threat_score(enrichment: EnrichmentResult) -> int:
    """
    Combine enrichment signals into a single 0-100 threat score.

    Scoring logic:
      - VirusTotal malicious detections are the strongest signal
      - AbuseIPDB confidence score is weighted heavily for IPs
      - Tor exit nodes get a bump
      - High report counts add smaller increments

    Returns an integer 0-100.
    """
    score = 0.0

    # ── VirusTotal signal (max ~60 points) ──────────────
    vt = enrichment.virustotal
    if vt and not vt.error and vt.total_engines > 0:
        # Ratio of engines flagging it as malicious
        malicious_ratio = vt.malicious_count / vt.total_engines
        suspicious_ratio = vt.suspicious_count / vt.total_engines

        # Malicious detections weighted more than suspicious
        score += malicious_ratio * 50
        score += suspicious_ratio * 20

        # Even a single malicious detection is meaningful
        if vt.malicious_count >= 1:
            score += 10
        if vt.malicious_count >= 5:
            score += 10

    # ── AbuseIPDB signal (max ~40 points) ───────────────
    abuse = enrichment.abuseipdb
    if abuse and not abuse.error:
        # Abuse confidence is already 0-100, scale to our budget
        score += (abuse.abuse_confidence_score / 100) * 35

        # Tor exit nodes are inherently higher risk in alerts
        if abuse.is_tor:
            score += 10

        # Whitelisted IPs (like major DNS) reduce score
        if abuse.is_whitelisted:
            score -= 20

    # Clamp to 0-100
    return max(0, min(100, int(round(score))))


def score_to_severity(score: int) -> str:
    """Map a numeric threat score to a severity label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"
