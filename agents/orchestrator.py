"""
Orchestrator (LangGraph)
========================
The triage workflow, built as a LangGraph state machine:

    parse -> (enrich, only if IOCs were found) -> mitre -> report

Tool routing in the enrich node is deterministic: each IOC is
routed to the tools that support its type. An IP gets VirusTotal +
AbuseIPDB + GeoIP; a file hash only gets VirusTotal. Private
(internal) IPs are never sent to external services. Rule-based
routing is a deliberate choice: in security triage, predictable and
auditable behaviour matters more than flexibility.

The LLM (Gemini) is used where rules fall short: catching
obfuscated IOCs and classifying the alert (parse node), and writing
the analysis narrative (report node).

The mitre node adds RAG: it retrieves relevant MITRE ATT&CK
techniques from a local vector store to ground the analysis.

LangGraph gives us:
  - A typed state object that flows through the graph
  - Clear, inspectable nodes
  - Conditional routing between nodes
  - Easy extensibility (add a node without rewiring everything)
"""

from __future__ import annotations
from typing import TypedDict, Optional
import asyncio
import ipaddress

from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI

from config import GEMINI_API_KEY, GEMINI_MODEL, LLM_TEMPERATURE
from models import (
    ParsedAlert, IOC, IOCType, EnrichmentResult, TriageReport, Severity,
)
from agents.parser import parse_alert
from tools import virustotal, abuseipdb, geolocation, mitre_search
from utils.scoring import compute_threat_score, score_to_severity


# -- Graph State --
# This dict flows through every node. Each node reads from it
# and writes its results back into it.

class SOCState(TypedDict):
    raw_alert: str
    parsed: Optional[ParsedAlert]
    enrichments: list[EnrichmentResult]
    mitre_techniques: list[dict]
    report: Optional[TriageReport]
    llm: object  # The LLM instance, passed through state


# -- LLM Factory --

def get_llm():
    """Create a Gemini LLM instance for the agent."""
    return ChatGoogleGenerativeAI(
        model=GEMINI_MODEL,
        google_api_key=GEMINI_API_KEY,
        temperature=LLM_TEMPERATURE,
    )


# -- Node 1: Parse --

async def parse_node(state: SOCState) -> SOCState:
    """Parse the raw alert into structured IOCs."""
    print("  [Node: parse] Extracting IOCs...")
    parsed = await parse_alert(state["raw_alert"], llm=state.get("llm"))
    state["parsed"] = parsed
    print(f"  [Node: parse] Found {len(parsed.iocs)} IOCs, "
          f"alert type: {parsed.alert_type}")
    return state


# -- Node 2: Enrich (the agentic core) --

# Internal network ranges. Sending these to external threat-intel
# services is pointless (they have no public reputation) and leaks
# details of our internal network to a third party.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # private
        "127.0.0.0/8",                                    # loopback
        "169.254.0.0/16",                                 # link-local
    )
]


def is_internal_ip(value: str) -> bool:
    """True if the IP belongs to a private/internal range."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _INTERNAL_NETWORKS)


def _select_tools_for_ioc(ioc: IOC) -> list[str]:
    """
    Decide which tools to call for an IOC, based on its type.

    Deterministic, rule-based routing (not an LLM decision):
      - Public IPs   -> VirusTotal + AbuseIPDB + GeoIP
      - Internal IPs -> none (kept in the report, not sent out)
      - Domains      -> VirusTotal only (AbuseIPDB/GeoIP are IP-only)
      - URLs         -> VirusTotal
      - Hashes       -> VirusTotal only (the others don't handle hashes)
      - Emails       -> none of these tools apply
    """
    if ioc.ioc_type == IOCType.IP:
        if is_internal_ip(ioc.value):
            return []
        return ["virustotal", "abuseipdb", "geolocation"]
    elif ioc.ioc_type == IOCType.DOMAIN:
        return ["virustotal"]
    elif ioc.ioc_type == IOCType.URL:
        return ["virustotal"]
    elif ioc.ioc_type in (IOCType.HASH_SHA256, IOCType.HASH_MD5, IOCType.HASH_SHA1):
        return ["virustotal"]
    else:  # EMAIL or anything else
        return []


def enrich_node(state: SOCState) -> SOCState:
    """
    For each IOC, route it to the right tools, call them,
    then compute a threat score.
    """
    print("  [Node: enrich] Enriching IOCs with threat intel...")
    parsed = state["parsed"]
    enrichments: list[EnrichmentResult] = []

    for ioc in parsed.iocs:
        tools_to_call = _select_tools_for_ioc(ioc)
        if ioc.ioc_type == IOCType.IP and is_internal_ip(ioc.value):
            reason = "internal IP, not sent to external services"
        else:
            reason = f"calling {tools_to_call or 'no tools'}"
        print(f"    -> {ioc.ioc_type.value} '{ioc.value}': {reason}")

        enrichment = EnrichmentResult(ioc=ioc)

        if "virustotal" in tools_to_call:
            enrichment.virustotal = virustotal.lookup_ioc(ioc)
        if "abuseipdb" in tools_to_call:
            enrichment.abuseipdb = abuseipdb.lookup_ip(ioc.value)
        if "geolocation" in tools_to_call:
            enrichment.geolocation = geolocation.lookup_ip(ioc.value)

        enrichment.threat_score = compute_threat_score(enrichment)
        enrichments.append(enrichment)

    state["enrichments"] = enrichments
    print(f"  [Node: enrich] Enriched {len(enrichments)} IOCs")
    return state


# -- Node 3: MITRE ATT&CK mapping (RAG) --

def mitre_node(state: SOCState) -> SOCState:
    """
    Retrieve relevant MITRE ATT&CK techniques for the alert.

    We build a query from the alert type + summary + IOC context,
    then semantically search the local MITRE vector store. This
    grounds the final analysis in real attack technique data
    instead of relying on the LLM's memory.
    """
    print("  [Node: mitre] Mapping to MITRE ATT&CK techniques...")
    parsed = state["parsed"]

    # Build a rich query from everything we know about the alert
    query_parts = [parsed.alert_type, parsed.summary]
    for ioc in parsed.iocs:
        if ioc.context:
            query_parts.append(ioc.context)
    query = ". ".join(p for p in query_parts if p)

    # Fall back to raw alert if we have little context
    if len(query.strip()) < 20:
        query = parsed.raw_text

    techniques = mitre_search.search_techniques(query, top_k=3)

    # Filter out any error entries
    techniques = [t for t in techniques if "error" not in t]

    state["mitre_techniques"] = techniques
    if techniques:
        print(f"  [Node: mitre] Mapped to {len(techniques)} techniques: "
              f"{', '.join(t['technique_id'] for t in techniques)}")
    else:
        print("  [Node: mitre] No techniques mapped (knowledge base may be empty)")
    return state


# -- Node 4: Report --

def _build_report_prompt(parsed, enrichments, mitre_techniques) -> str:
    """Build the prompt asking the LLM to write the analysis narrative."""
    findings = []
    for e in enrichments:
        parts = [f"IOC: {e.ioc.value} ({e.ioc.ioc_type.value})"]
        parts.append(f"  Threat score: {e.threat_score}/100")
        if e.virustotal and not e.virustotal.error:
            parts.append(
                f"  VirusTotal: {e.virustotal.malicious_count}/"
                f"{e.virustotal.total_engines} engines flagged malicious"
            )
        if e.abuseipdb and not e.abuseipdb.error:
            parts.append(
                f"  AbuseIPDB: {e.abuseipdb.abuse_confidence_score}% abuse "
                f"confidence, {e.abuseipdb.total_reports} reports"
            )
        if e.geolocation and not e.geolocation.error:
            parts.append(
                f"  Location: {e.geolocation.city}, {e.geolocation.country} "
                f"({e.geolocation.isp})"
            )
        findings.append("\n".join(parts))

    findings_text = "\n\n".join(findings) if findings else "No enrichment data."

    # Include the MITRE techniques we retrieved
    mitre_text = "None mapped."
    if mitre_techniques:
        mitre_text = "\n".join(
            f"  {t['technique_id']} {t['name']} (tactics: {t['tactics']})"
            for t in mitre_techniques
        )

    return f"""You are a senior SOC analyst writing an incident triage report.

ORIGINAL ALERT:
{parsed.raw_text}

ALERT TYPE: {parsed.alert_type}

ENRICHMENT FINDINGS:
{findings_text}

RELEVANT MITRE ATT&CK TECHNIQUES (retrieved from knowledge base):
{mitre_text}

Write a concise triage analysis that references the MITRE techniques where relevant.
Respond ONLY in this JSON format, no markdown:
{{
    "analysis": "2-4 sentence narrative explaining what this alert means, what the enrichment revealed, the likely threat, and which MITRE techniques apply",
    "recommended_actions": ["action 1", "action 2", "action 3"]
}}"""


async def report_node(state: SOCState) -> SOCState:
    """Generate the final triage report with LLM-written analysis."""
    print("  [Node: report] Generating triage report...")
    import json
    import re
    from datetime import datetime

    parsed = state["parsed"]
    enrichments = state["enrichments"]
    mitre_techniques = state.get("mitre_techniques", [])
    llm = state.get("llm")

    max_score = max((e.threat_score for e in enrichments), default=0)
    severity = Severity(score_to_severity(max_score))

    analysis = ""
    recommended_actions = []

    if llm is not None:
        prompt = _build_report_prompt(parsed, enrichments, mitre_techniques)
        try:
            response = await llm.ainvoke(prompt)
            text = response.content if hasattr(response, "content") else str(response)
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)
            data = json.loads(cleaned)
            analysis = data.get("analysis", "")
            recommended_actions = data.get("recommended_actions", [])
        except Exception as e:
            analysis = f"Automated analysis based on enrichment data. (LLM narrative unavailable: {e})"
            recommended_actions = [
                "Review the IOC enrichment data manually",
                "Correlate with other recent alerts",
                "Escalate if threat scores are elevated",
            ]

    # Format MITRE techniques for the report model
    mitre_for_report = [
        {
            "id": t["technique_id"],
            "name": t["name"],
            "tactic": t["tactics"],
            "description": t.get("description", ""),
        }
        for t in mitre_techniques
    ]

    report = TriageReport(
        report_id=f"SOC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        alert_summary=parsed.summary,
        alert_type=parsed.alert_type,
        severity=severity,
        confidence_score=max_score,
        iocs_found=parsed.iocs,
        enrichments=enrichments,
        mitre_techniques=mitre_for_report,
        analysis=analysis,
        recommended_actions=recommended_actions,
        raw_alert=state["raw_alert"],
    )
    state["report"] = report
    print(f"  [Node: report] Report complete. Severity: {severity.value}")
    return state


# -- Routing --

def route_after_parse(state: SOCState) -> str:
    """
    Conditional edge: only run enrichment if parsing found IOCs.
    With nothing to look up, skip straight to MITRE mapping and
    avoid wasting rate-limited API calls.
    """
    parsed = state.get("parsed")
    if parsed and parsed.iocs:
        return "enrich"
    print("  [Router] No IOCs found, skipping enrichment")
    return "mitre"


# -- Build the Graph --

def build_soc_graph():
    """
    Wire the nodes into a LangGraph state machine.

    Flow: parse -> [enrich if IOCs found] -> mitre -> report -> END
    """
    graph = StateGraph(SOCState)

    graph.add_node("parse", parse_node)
    graph.add_node("enrich", enrich_node)
    graph.add_node("mitre", mitre_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("parse")
    graph.add_conditional_edges(
        "parse",
        route_after_parse,
        {"enrich": "enrich", "mitre": "mitre"},
    )
    graph.add_edge("enrich", "mitre")
    graph.add_edge("mitre", "report")
    graph.add_edge("report", END)

    return graph.compile()


# -- Main entry point --

async def analyze_alert(raw_alert: str, use_llm: bool = True) -> TriageReport:
    """
    Run a raw alert through the full SOC triage pipeline.

    Args:
        raw_alert: The raw security alert text
        use_llm: Whether to use the Gemini LLM (set False for offline testing)

    Returns:
        A complete TriageReport.
    """
    app = build_soc_graph()

    initial_state: SOCState = {
        "raw_alert": raw_alert,
        "parsed": None,
        "enrichments": [],
        "mitre_techniques": [],
        "report": None,
        "llm": get_llm() if use_llm else None,
    }

    final_state = await app.ainvoke(initial_state)
    return final_state["report"]


# -- Quick test --
if __name__ == "__main__":
    from config import SAMPLE_ALERTS

    async def main():
        print("=" * 60)
        print("ORCHESTRATOR TEST -- Full Pipeline (with MITRE)")
        print("=" * 60)

        alert = SAMPLE_ALERTS["firewall_alert"]
        print(f"\nAnalyzing firewall alert...\n")

        report = await analyze_alert(alert, use_llm=True)

        print("\n" + "=" * 60)
        print("TRIAGE REPORT")
        print("=" * 60)
        print(f"Report ID:   {report.report_id}")
        print(f"Alert Type:  {report.alert_type}")
        print(f"Severity:    {report.severity.value}")
        print(f"Confidence:  {report.confidence_score}/100")
        print(f"\nIOCs Found:  {len(report.iocs_found)}")
        for ioc in report.iocs_found:
            print(f"  - [{ioc.ioc_type.value}] {ioc.value}")
        print(f"\nMITRE ATT&CK Techniques:")
        for t in report.mitre_techniques:
            print(f"  - {t['id']} {t['name']} ({t['tactic']})")
        print(f"\nAnalysis:\n  {report.analysis}")
        print(f"\nRecommended Actions:")
        for i, action in enumerate(report.recommended_actions, 1):
            print(f"  {i}. {action}")
        print("=" * 60)

    asyncio.run(main())
