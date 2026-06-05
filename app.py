"""
Agentic SOC Assistant -- Streamlit UI
=====================================
A clean, dark-themed security operations dashboard.

Paste a raw security alert, and the agent runs the full pipeline:
parse -> enrich -> MITRE mapping -> triage report.

Run with:  streamlit run app.py
"""

import asyncio
import streamlit as st

from config import SAMPLE_ALERTS
from agents.orchestrator import analyze_alert
from models import Severity


# -- Page config --
st.set_page_config(
    page_title="Agentic SOC Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -- Custom styling --
# A dark SOC-console aesthetic: near-black background, cyan accents,
# monospace touches for that terminal/security-tool feel.
st.markdown("""
<style>
    /* Severity badge colors */
    .sev-CRITICAL { background:#7f1d1d; color:#fecaca; }
    .sev-HIGH     { background:#7c2d12; color:#fed7aa; }
    .sev-MEDIUM   { background:#78350f; color:#fde68a; }
    .sev-LOW      { background:#14532d; color:#bbf7d0; }
    .sev-INFO     { background:#1e3a5f; color:#bfdbfe; }

    .sev-badge {
        display:inline-block;
        padding:6px 18px;
        border-radius:6px;
        font-weight:700;
        font-size:1.1rem;
        letter-spacing:0.05em;
    }

    .ioc-pill {
        display:inline-block;
        background:#1f2937;
        border:1px solid #374151;
        border-radius:6px;
        padding:4px 10px;
        margin:3px;
        font-family:monospace;
        font-size:0.85rem;
        color:#e5e7eb;
    }

    .mitre-card {
        background:#111827;
        border-left:3px solid #06b6d4;
        border-radius:4px;
        padding:10px 14px;
        margin:6px 0;
    }
    .mitre-id { color:#06b6d4; font-weight:700; font-family:monospace; }

    .section-header {
        color:#06b6d4;
        font-size:1.1rem;
        font-weight:700;
        border-bottom:1px solid #1f2937;
        padding-bottom:6px;
        margin-top:18px;
    }
</style>
""", unsafe_allow_html=True)


# -- Sidebar --
with st.sidebar:
    st.title("🛡️ SOC Assistant")
    st.caption("Autonomous alert triage powered by LangGraph + Gemini")

    st.markdown("---")
    st.subheader("Load a sample alert")

    sample_choice = st.selectbox(
        "Choose a sample to test with:",
        ["-- None --"] + list(SAMPLE_ALERTS.keys()),
        format_func=lambda x: x.replace("_", " ").title(),
    )

    st.markdown("---")
    use_llm = st.toggle("Use LLM analysis (Gemini)", value=True,
                        help="Turn off for faster, offline regex+enrichment only")

    st.markdown("---")
    st.caption("**Pipeline:** parse → enrich → MITRE → report")
    st.caption("**Tools:** VirusTotal · AbuseIPDB · GeoIP")
    st.caption("**Knowledge base:** MITRE ATT&CK (ChromaDB)")


# -- Main area --
st.title("Security Alert Triage")
st.caption("Paste a raw alert below. The agent will extract IOCs, enrich them with "
           "live threat intelligence, map findings to MITRE ATT&CK, and generate a triage report.")

# Pre-fill with sample if chosen
default_text = ""
if sample_choice != "-- None --":
    default_text = SAMPLE_ALERTS[sample_choice].strip()

alert_text = st.text_area(
    "Raw security alert",
    value=default_text,
    height=220,
    placeholder="Paste a firewall log, phishing email, IDS alert, etc...",
)

analyze_clicked = st.button("🔍 Analyze Alert", type="primary", use_container_width=True)


# -- Severity badge helper --
def severity_badge(severity: Severity) -> str:
    return (f'<span class="sev-badge sev-{severity.value}">'
            f'{severity.value}</span>')


# -- Run analysis --
if analyze_clicked:
    if not alert_text.strip():
        st.warning("Please paste an alert or choose a sample first.")
    else:
        with st.spinner("Running triage pipeline... (parsing, enriching, mapping)"):
            # Streamlit runs sync; bridge to our async pipeline
            report = asyncio.run(analyze_alert(alert_text, use_llm=use_llm))

        st.success("Triage complete.")

        # -- Top summary row --
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("**Severity**")
            st.markdown(severity_badge(report.severity), unsafe_allow_html=True)
        with col2:
            st.metric("Confidence", f"{report.confidence_score}/100")
        with col3:
            st.metric("IOCs Found", len(report.iocs_found))
        with col4:
            st.metric("Alert Type", report.alert_type.replace("_", " ").title())

        # -- Analysis narrative --
        st.markdown('<div class="section-header">Analysis</div>',
                    unsafe_allow_html=True)
        st.write(report.analysis or "_No analysis generated._")

        # -- Recommended actions --
        if report.recommended_actions:
            st.markdown('<div class="section-header">Recommended Actions</div>',
                        unsafe_allow_html=True)
            for i, action in enumerate(report.recommended_actions, 1):
                st.markdown(f"**{i}.** {action}")

        # -- Two-column detail row --
        left, right = st.columns(2)

        # IOCs + enrichment
        with left:
            st.markdown('<div class="section-header">Indicators of Compromise</div>',
                        unsafe_allow_html=True)
            for enr in report.enrichments:
                ioc = enr.ioc
                st.markdown(
                    f'<span class="ioc-pill">[{ioc.ioc_type.value}] '
                    f'{ioc.value} · score {enr.threat_score}/100</span>',
                    unsafe_allow_html=True,
                )
                # Show enrichment details in an expander
                with st.expander(f"Details: {ioc.value}"):
                    if enr.virustotal and not enr.virustotal.error:
                        vt = enr.virustotal
                        st.write(f"**VirusTotal:** {vt.malicious_count}/"
                                 f"{vt.total_engines} engines flagged malicious")
                    if enr.abuseipdb and not enr.abuseipdb.error:
                        ab = enr.abuseipdb
                        st.write(f"**AbuseIPDB:** {ab.abuse_confidence_score}% "
                                 f"abuse confidence, {ab.total_reports} reports")
                    if enr.geolocation and not enr.geolocation.error:
                        geo = enr.geolocation
                        st.write(f"**Location:** {geo.city}, {geo.country} "
                                 f"({geo.isp})")
                    if ioc.context:
                        st.caption(ioc.context)

        # MITRE techniques
        with right:
            st.markdown('<div class="section-header">MITRE ATT&CK Techniques</div>',
                        unsafe_allow_html=True)
            if report.mitre_techniques:
                for t in report.mitre_techniques:
                    st.markdown(
                        f'<div class="mitre-card">'
                        f'<span class="mitre-id">{t["id"]}</span> '
                        f'{t["name"]}<br>'
                        f'<small style="color:#9ca3af">Tactics: {t["tactic"]}</small>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.caption("No techniques mapped.")

        # -- Raw report ID footer --
        st.markdown("---")
        st.caption(f"Report ID: {report.report_id} · Generated {report.generated_at}")
