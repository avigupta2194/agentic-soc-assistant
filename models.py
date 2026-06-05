"""
Data models for the Agentic SOC Assistant.
These Pydantic models enforce structure across the entire pipeline --
from parsed IOCs to the final triage report.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


# -- Enums --

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "sha256"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    EMAIL = "email"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# -- IOC Models --

class IOC(BaseModel):
    """A single Indicator of Compromise extracted from an alert."""
    value: str
    ioc_type: IOCType
    context: str = ""  # Where in the alert this was found


class ParsedAlert(BaseModel):
    """Result of parsing a raw security alert."""
    raw_text: str
    alert_type: str = "unknown"  # phishing, firewall, IDS, etc.
    iocs: list[IOC] = []
    timestamp: Optional[str] = None
    summary: str = ""


# -- Enrichment Models --
# Note: string fields default to "" but are also Optional so a null
# from an upstream API (e.g. private IPs on AbuseIPDB) never breaks validation.

class VirusTotalResult(BaseModel):
    """Enrichment data from VirusTotal."""
    ioc_value: str
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    total_engines: int = 0
    reputation_score: int = 0
    tags: list[str] = []
    last_analysis_date: Optional[str] = None
    error: Optional[str] = None


class AbuseIPDBResult(BaseModel):
    """Enrichment data from AbuseIPDB."""
    ip_address: str
    abuse_confidence_score: int = 0
    total_reports: int = 0
    country_code: Optional[str] = ""
    isp: Optional[str] = ""
    domain: Optional[str] = ""
    is_tor: bool = False
    is_whitelisted: bool = False
    last_reported_at: Optional[str] = None
    error: Optional[str] = None


class GeoLocation(BaseModel):
    """IP geolocation data."""
    ip_address: str
    country: Optional[str] = ""
    region: Optional[str] = ""
    city: Optional[str] = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: Optional[str] = ""
    org: Optional[str] = ""
    error: Optional[str] = None


class EnrichmentResult(BaseModel):
    """Combined enrichment data for a single IOC."""
    ioc: IOC
    virustotal: Optional[VirusTotalResult] = None
    abuseipdb: Optional[AbuseIPDBResult] = None
    geolocation: Optional[GeoLocation] = None
    mitre_techniques: list[str] = []
    threat_score: int = 0  # 0-100 computed score


# -- Final Report Model --

class TriageReport(BaseModel):
    """The final structured incident triage report."""
    report_id: str = ""
    generated_at: str = Field(
        default_factory=lambda: datetime.now().isoformat()
    )
    alert_summary: str = ""
    alert_type: str = ""
    severity: Severity = Severity.INFO
    confidence_score: int = 0  # 0-100
    iocs_found: list[IOC] = []
    enrichments: list[EnrichmentResult] = []
    mitre_techniques: list[dict] = []  # {id, name, tactic, description}
    analysis: str = ""  # LLM-generated analysis narrative
    recommended_actions: list[str] = []
    raw_alert: str = ""
