"""
Alert Parser Agent
==================
Takes a raw security alert (email, firewall log, IDS alert, etc.)
and extracts all Indicators of Compromise (IOCs) from it.

Uses a two-pass approach:
  1. Regex pass — catches well-structured IOCs reliably
  2. LLM pass  — catches IOCs the regex missed and classifies the alert type

This two-pass design is intentional: regex gives you precision,
the LLM gives you recall and context understanding.
"""

import re
import json
from models import IOC, IOCType, ParsedAlert

# ── Regex patterns for IOC extraction ─────────────────────

# IPv4 address (excludes common private/loopback unless in alert context)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Domain names (e.g., malicious-domain.xyz, paypa1.com)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|xyz|io|info|biz|ru|cn|top|tk|ml|ga|cf|gq|"
    r"cc|pw|club|online|site|tech|space|fun|icu|buzz|dev|app|"
    r"co|me|tv|edu|gov|mil|int)\b"
)

# URLs (http/https/ftp)
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|ftp://[^\s<>\"')\]]+"
)

# SHA256 hash (64 hex characters)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# MD5 hash (32 hex characters)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

# SHA1 hash (40 hex characters)
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")

# Email addresses
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Patterns to skip (common false positives)
SKIP_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "company.com", "example.com", "localhost",
}


def extract_iocs_regex(raw_text: str) -> list[IOC]:
    """
    First pass: extract IOCs using regex patterns.
    Fast, reliable, but can miss context-dependent indicators.
    """
    iocs = []
    seen_values = set()

    def add_ioc(value: str, ioc_type: IOCType, context: str = ""):
        """Add an IOC if we haven't seen it before."""
        normalized = value.lower().strip()
        if normalized not in seen_values:
            seen_values.add(normalized)
            iocs.append(IOC(value=value, ioc_type=ioc_type, context=context))

    # Extract URLs first (so we can avoid double-counting domains in URLs)
    url_domains = set()
    for match in URL_PATTERN.finditer(raw_text):
        url = match.group()
        add_ioc(url, IOCType.URL, "Found in alert text")
        # Extract domain from URL to avoid double-counting
        domain_match = re.search(r"https?://([^/:]+)", url)
        if domain_match:
            url_domains.add(domain_match.group(1).lower())

    # Extract IPs
    for match in IP_PATTERN.finditer(raw_text):
        ip = match.group()
        add_ioc(ip, IOCType.IP, "Found in alert text")

    # Extract domains (skip those already captured via URLs)
    for match in DOMAIN_PATTERN.finditer(raw_text):
        domain = match.group()
        if (domain.lower() not in SKIP_DOMAINS
                and domain.lower() not in url_domains):
            add_ioc(domain, IOCType.DOMAIN, "Found in alert text")

    # Extract hashes (check SHA256 first, then SHA1, then MD5 to avoid
    # substring matches — a SHA256 contains what looks like an MD5)
    sha256_values = set()
    for match in SHA256_PATTERN.finditer(raw_text):
        value = match.group()
        sha256_values.add(value.lower())
        add_ioc(value, IOCType.HASH_SHA256, "Found in alert text")

    sha1_values = set()
    for match in SHA1_PATTERN.finditer(raw_text):
        value = match.group()
        # Skip if this is a substring of an already-found SHA256
        if not any(value.lower() in s for s in sha256_values):
            sha1_values.add(value.lower())
            add_ioc(value, IOCType.HASH_SHA1, "Found in alert text")

    for match in MD5_PATTERN.finditer(raw_text):
        value = match.group()
        # Skip if substring of SHA256 or SHA1
        if (not any(value.lower() in s for s in sha256_values)
                and not any(value.lower() in s for s in sha1_values)):
            add_ioc(value, IOCType.HASH_MD5, "Found in alert text")

    # Extract emails
    for match in EMAIL_PATTERN.finditer(raw_text):
        email = match.group()
        add_ioc(email, IOCType.EMAIL, "Found in alert text")

    return iocs


def build_llm_parser_prompt(raw_text: str, regex_iocs: list[IOC]) -> str:
    """
    Build the prompt for the LLM second pass.
    We give it the raw alert AND the regex results, asking it to:
      1. Classify the alert type
      2. Find any IOCs the regex missed
      3. Add context to each IOC
      4. Provide a brief summary
    """
    regex_summary = "None found" if not regex_iocs else "\n".join(
        f"  - {ioc.ioc_type.value}: {ioc.value}" for ioc in regex_iocs
    )

    return f"""You are a senior SOC analyst. Analyze this raw security alert and extract information.

RAW ALERT:
{raw_text}

REGEX ALREADY FOUND THESE IOCs:
{regex_summary}

Your job:
1. Classify the alert type (one of: phishing, firewall, ids, malware, brute_force, data_exfil, c2_communication, unknown)
2. Find any IOCs the regex MISSED (look for obfuscated IPs, defanged URLs like hXXp://, encoded domains, etc.)
3. For each IOC (both regex-found and new), provide context about WHY it's suspicious in this alert
4. Write a 1-2 sentence summary of what this alert is about

Respond ONLY in this exact JSON format, no markdown, no backticks:
{{
    "alert_type": "phishing",
    "summary": "Brief description of the alert",
    "timestamp": "extracted timestamp or null",
    "additional_iocs": [
        {{
            "value": "the IOC value",
            "ioc_type": "ip|domain|url|sha256|md5|sha1|email",
            "context": "why this is suspicious"
        }}
    ],
    "ioc_context_updates": [
        {{
            "value": "existing IOC value from regex",
            "context": "updated context about why this is suspicious"
        }}
    ]
}}"""


def parse_llm_response(
    response_text: str,
    regex_iocs: list[IOC],
    raw_text: str,
) -> ParsedAlert:
    """
    Parse the LLM's JSON response and merge with regex IOCs.
    Handles malformed JSON gracefully.
    """
    # Default values in case LLM response is unusable
    alert_type = "unknown"
    summary = ""
    timestamp = None
    all_iocs = list(regex_iocs)  # Start with regex results

    try:
        # Clean potential markdown fencing
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        data = json.loads(cleaned)

        alert_type = data.get("alert_type", "unknown")
        summary = data.get("summary", "")
        timestamp = data.get("timestamp")

        # Add any new IOCs the LLM found
        ioc_type_map = {
            "ip": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "sha256": IOCType.HASH_SHA256,
            "md5": IOCType.HASH_MD5,
            "sha1": IOCType.HASH_SHA1,
            "email": IOCType.EMAIL,
        }

        existing_values = {ioc.value.lower() for ioc in all_iocs}

        for new_ioc in data.get("additional_iocs", []):
            value = new_ioc.get("value", "")
            if value.lower() not in existing_values:
                ioc_type_str = new_ioc.get("ioc_type", "").lower()
                if ioc_type_str in ioc_type_map:
                    all_iocs.append(IOC(
                        value=value,
                        ioc_type=ioc_type_map[ioc_type_str],
                        context=new_ioc.get("context", "Found by LLM analysis"),
                    ))
                    existing_values.add(value.lower())

        # Update context for existing IOCs
        context_map = {
            item["value"].lower(): item["context"]
            for item in data.get("ioc_context_updates", [])
            if "value" in item and "context" in item
        }
        for ioc in all_iocs:
            if ioc.value.lower() in context_map:
                ioc.context = context_map[ioc.value.lower()]

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        # If LLM response is malformed, we still have regex IOCs
        summary = f"LLM parsing failed ({e}), using regex-only results."

    return ParsedAlert(
        raw_text=raw_text,
        alert_type=alert_type,
        iocs=all_iocs,
        timestamp=timestamp,
        summary=summary,
    )


async def parse_alert(raw_text: str, llm=None) -> ParsedAlert:
    """
    Main entry point: parse a raw security alert.

    Args:
        raw_text: The raw alert text (email, log, IDS output, etc.)
        llm: Optional LangChain LLM instance. If None, uses regex only.

    Returns:
        ParsedAlert with extracted IOCs and classification.
    """
    # Pass 1: Regex extraction
    regex_iocs = extract_iocs_regex(raw_text)

    # Pass 2: LLM enhancement (if available)
    if llm is not None:
        prompt = build_llm_parser_prompt(raw_text, regex_iocs)
        try:
            response = await llm.ainvoke(prompt)
            # Handle both string and AIMessage responses
            response_text = (
                response.content
                if hasattr(response, "content")
                else str(response)
            )
            return parse_llm_response(response_text, regex_iocs, raw_text)
        except Exception as e:
            # LLM failed — fall back to regex-only results
            return ParsedAlert(
                raw_text=raw_text,
                alert_type="unknown",
                iocs=regex_iocs,
                summary=f"LLM unavailable ({e}), using regex-only extraction.",
            )

    # No LLM provided — return regex-only results
    return ParsedAlert(
        raw_text=raw_text,
        alert_type="unknown",
        iocs=regex_iocs,
        summary="Regex-only extraction (no LLM configured).",
    )


# ── Quick test ────────────────────────────────────────────
if __name__ == "__main__":
    from config import SAMPLE_ALERTS

    print("=" * 60)
    print("ALERT PARSER — REGEX TEST")
    print("=" * 60)

    for name, alert_text in SAMPLE_ALERTS.items():
        print(f"\n{'─' * 40}")
        print(f"Testing: {name}")
        print(f"{'─' * 40}")

        iocs = extract_iocs_regex(alert_text)

        if not iocs:
            print("  No IOCs found.")
        else:
            for ioc in iocs:
                print(f"  [{ioc.ioc_type.value:>8}]  {ioc.value}")

    print(f"\n{'=' * 60}")
    print("All regex tests complete.")
    print("Run with LLM for full two-pass extraction.")
    print(f"{'=' * 60}")
