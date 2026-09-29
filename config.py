"""
Centralized configuration for the Agentic SOC Assistant.
All settings, API endpoints, and constants live here.
"""

import os
from dotenv import load_dotenv

load_dotenv()


# ── API Keys ──────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


# ── API Endpoints ─────────────────────────────────────────
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
IP_API_BASE_URL = "http://ip-api.com/json"


# ── Rate Limits (requests per minute) ────────────────────
VIRUSTOTAL_RATE_LIMIT = 4    # Free tier: 4 req/min
ABUSEIPDB_RATE_LIMIT = 60    # Free tier: generous
IP_API_RATE_LIMIT = 45       # Free tier: 45 req/min


# ── LLM Settings ─────────────────────────────────────────
GEMINI_MODEL = "gemini-2.5-flash"   # Free, fast, good at function calling
LLM_TEMPERATURE = 0.1               # Low temp for consistent analysis
LLM_MAX_RETRIES = 3


# ── ChromaDB Settings ────────────────────────────────────
CHROMA_PERSIST_DIR = "./chroma_db"
CHROMA_COLLECTION_NAME = "mitre_attack"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # Fast, free, runs locally

# Drop MITRE matches weaker than this. ChromaDB returns a distance
# (lower = more similar). Calibrate by running:
#   python -m tools.mitre_search
# and checking the relevance values printed for good vs bad matches.
MITRE_MAX_DISTANCE = 0.7


# ── Severity Thresholds ──────────────────────────────────
SEVERITY_LEVELS = {
    "CRITICAL": {"min_score": 80, "color": "#FF0000"},
    "HIGH":     {"min_score": 60, "color": "#FF6600"},
    "MEDIUM":   {"min_score": 40, "color": "#FFAA00"},
    "LOW":      {"min_score": 20, "color": "#00AA00"},
    "INFO":     {"min_score": 0,  "color": "#0066CC"},
}


# ── Sample Alerts (for testing & demo) ───────────────────
SAMPLE_ALERTS = {
    "phishing_email": """
        From: security-alert@paypa1.com
        To: employee@company.com
        Subject: Urgent: Your account has been compromised

        Dear User,
        We detected unauthorized access from IP 185.220.101.34.
        Click here to verify: http://paypa1-secure.malicious-domain.xyz/verify
        Your account will be locked in 24 hours.
        Reference ID: TXN-2024-88431
    """,
    "firewall_alert": """
        [ALERT] Firewall Rule Triggered
        Timestamp: 2025-01-15T14:32:07Z
        Source IP: 45.33.32.156
        Destination IP: 10.0.1.50
        Destination Port: 443
        Protocol: TCP
        Action: BLOCK
        Rule: Outbound C2 Communication Detected
        Bytes Transferred: 4,521
        Connection Duration: 0.8s
        Repeat Offenses: 14 in last hour
    """,
    "ids_alert": """
        [SNORT] [1:2024217:3] ET MALWARE Win32/Emotet Activity (POST)
        Classification: A Network Trojan was detected
        Priority: 1
        Timestamp: 2025-01-15 09:17:44
        Source: 192.168.1.105:49232
        Destination: 203.0.113.42:8080
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Additional: Multiple DNS queries to DGA domains observed from same host
    """,
}
