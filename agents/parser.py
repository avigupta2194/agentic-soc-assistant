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
import ipaddress
from models import IOC, IOCType, ParsedAlert

# ── Regex patterns for IOC extraction ─────────────────────

# IPv4 address (private IPs are extracted here; the enrich step skips them)
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


# ── Refanging + validation (used to check LLM-found IOCs) ──

def refang(text: str) -> str:
    """
    Turn defanged indicators back into their normal form.
    Analysts "defang" IOCs so they can't be clicked by accident,
    e.g. hxxp://evil[.]com or 1.2.3[.]4. We need the real form
    to compare against the alert and to query threat intel.
    """
    t = re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)
    for fake, real in (("[.]", "."), ("(.)", "."), ("[dot]", "."),
                       ("[:]", ":"), ("[at]", "@"), ("[@]", "@")):
        t = t.replace(fake, real)
    return t


_HEX = {
    IOCType.HASH_SHA256: re.compile(r"[a-fA-F0-9]{64}"),
    IOCType.HASH_SHA1: re.compile(r"[a-fA-F0-9]{40}"),
    IOCType.HASH_MD5: re.compile(r"[a-fA-F0-9]{32}"),
}
_GENERIC_DOMAIN = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)


def is_valid_format(value: str, ioc_type: IOCType) -> bool:
    """Check that an IOC actually looks like the type it claims to be."""
    if ioc_type == IOCType.IP:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if ioc_type in _HEX:
        return bool(_HEX[ioc_type].fullmatch(value))
    if ioc_type == IOCType.DOMAIN:
        return bool(_GENERIC_DOMAIN.fullmatch(value))
    if ioc_type == IOCType.URL:
        return bool(re.match(r"(?:https?|ftp)://\S+$", value))
    if ioc_type == IOCType.EMAIL:
        return bool(EMAIL_PATTERN.fullmatch(value))
    return False


def appears_in_alert(value: str, raw_text: str) -> bool:
    """
    Grounding check: the IOC must literally appear in the alert
    (after refanging both sides). This stops the LLM from adding
    indicators it made up.
    """
    return refang(value).lower() in refang(raw_text).lower()


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
    rejected: list[str] = []     # LLM IOCs that failed validation

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
            # Refang so we store the real, queryable form
            value = refang(str(new_ioc.get("value", "")).strip())
            ioc_type_str = str(new_ioc.get("ioc_type", "")).lower()

            if not value or value.lower() in existing_values:
                continue
            if ioc_type_str not in ioc_type_map:
                rejected.append(f"{value} (unknown type '{ioc_type_str}')")
                continue
            ioc_type = ioc_type_map[ioc_type_str]

            # Check 1: does it look like what it claims to be?
            if not is_valid_format(value, ioc_type):
                rejected.append(f"{value} (invalid {ioc_type.value} format)")
                continue
            # Check 2: is it actually in the alert? (anti-hallucination)
            if not appears_in_alert(value, raw_text):
                rejected.append(f"{value} (not found in alert text)")
                continue

            all_iocs.append(IOC(
                value=value,
                ioc_type=ioc_type,
                context=new_ioc.get("context", "Found by LLM analysis"),
            ))
            existing_values.add(value.lower())

        if rejected:
            print(f"  [parser] Rejected {len(rejected)} LLM IOC(s): {rejected}")

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
        rejected_llm_iocs=rejected,
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
