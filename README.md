# 🛡️ Agentic SOC Assistant

An autonomous Security Operations Center (SOC) analyst built with **LangGraph** and **Google Gemini**. Paste a raw security alert — a firewall log, phishing email, or IDS alert — and the agent autonomously extracts indicators of compromise, decides which threat-intelligence tools to query, maps findings to the MITRE ATT&CK framework, and produces a structured triage report with a severity rating and recommended response actions.

Unlike a hardcoded enrichment pipeline, this agent *reasons* about each indicator and chooses appropriate tools per IOC type. That autonomous decision-making is the core of what makes it agentic.

---

## ✨ Key Features

- **Autonomous tool selection** — the agent inspects each IOC and decides which tools to invoke (an IP gets full enrichment; a file hash only goes to VirusTotal; an email skips network tools entirely).
- **Live threat intelligence** — real-time enrichment via VirusTotal, AbuseIPDB, and IP geolocation.
- **RAG over MITRE ATT&CK** — semantic retrieval against a local ChromaDB vector store of 690+ attack techniques, grounding the analysis in real framework data rather than model memory.
- **LLM-written triage narrative** — Gemini synthesizes the enrichment + retrieved techniques into a concise analyst-style report.
- **Deterministic threat scoring** — a rule-based 0–100 score (separate from the LLM) keeps severity explainable and consistent.
- **Graceful degradation** — rate limits, API failures, and malformed LLM responses are all handled without crashing; the agent always produces a usable report.
- **Clean SOC dashboard** — a dark-themed Streamlit UI with severity badges, IOC detail panels, and MITRE technique cards.

---

## 🏗️ Architecture

The pipeline is a **LangGraph state machine** with four nodes:

```
Raw Alert
   │
   ▼
[ parse ]   Extract IOCs (regex + LLM two-pass), classify alert type
   │
   ▼
[ enrich ]  AUTONOMOUS: per-IOC tool selection → VirusTotal / AbuseIPDB / GeoIP
   │         + deterministic 0–100 threat scoring
   ▼
[ mitre ]   RAG: semantic search over MITRE ATT&CK (ChromaDB) for relevant techniques
   │
   ▼
[ report ]  LLM synthesizes a grounded triage report (severity, analysis, actions)
   │
   ▼
Triage Report
```

A typed state object flows through each node, so the graph is easy to inspect, debug, and extend.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | LangGraph |
| LLM | Google Gemini (2.5 Flash) |
| Vector database | ChromaDB (local) |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) |
| Threat intel | VirusTotal · AbuseIPDB · ip-api.com |
| Knowledge base | MITRE ATT&CK Enterprise |
| Data validation | Pydantic v2 |
| Frontend | Streamlit |

---

## 🚀 Getting Started

### 1. Clone and set up the environment

```bash
git clone https://github.com/YOUR_USERNAME/agentic-soc-assistant.git
cd agentic-soc-assistant

python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Get your free API keys

All three are free, no credit card required:

| Service | Free tier | Where |
|---------|-----------|-------|
| Google Gemini | generous daily quota | https://aistudio.google.com/apikey |
| VirusTotal | 4 lookups/min, 500/day | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/register |

### 3. Configure environment variables

```bash
cp .env.example .env   # then paste your keys into .env
```

### 4. Build the MITRE ATT&CK knowledge base (one-time)

```bash
python -m data.load_mitre
```

Downloads the official MITRE ATT&CK dataset and embeds ~690 techniques into a local ChromaDB store. Takes a couple of minutes.

### 5. Run the app

```bash
streamlit run app.py
```

Open http://localhost:8501, pick a sample alert from the sidebar, and hit **Analyze Alert**.

---

## 📁 Project Structure

```
agentic-soc-assistant/
├── app.py                  # Streamlit UI
├── config.py               # Settings, endpoints, sample alerts
├── models.py               # Pydantic data models
├── agents/
│   ├── parser.py           # Two-pass IOC extraction (regex + LLM)
│   └── orchestrator.py     # LangGraph state machine (the agent)
├── tools/
│   ├── virustotal.py       # VirusTotal client
│   ├── abuseipdb.py        # AbuseIPDB client
│   ├── geolocation.py      # IP geolocation
│   └── mitre_search.py     # MITRE ATT&CK vector search (RAG)
├── data/
│   └── load_mitre.py       # MITRE knowledge-base loader
├── utils/
│   ├── rate_limiter.py     # API rate limiting
│   └── scoring.py          # Deterministic threat scoring
└── .streamlit/
    └── config.toml         # Theme + watcher config
```

---

## 🧪 How It Works (Design Notes)

**Why two-pass parsing?** Regex gives precise, fast extraction of well-formed IOCs; the LLM pass catches obfuscated/defanged indicators and classifies the alert. Regex for precision, LLM for recall.

**Why is scoring rule-based, not LLM-based?** Threat scores need to be consistent and explainable. The LLM writes the narrative; deterministic rules produce the number. They're computed independently, which also surfaces useful disagreements between qualitative and quantitative assessments.

**Why RAG for MITRE?** Asking an LLM to recall technique IDs from memory invites hallucination. Retrieving them from a curated vector store grounds the analysis in authoritative data.

---

## 📄 License

MIT
