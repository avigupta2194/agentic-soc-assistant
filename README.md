# 🛡️ Agentic SOC Assistant

An AI-assisted Security Operations Center (SOC) triage workflow built with **LangGraph** and **Google Gemini**. Paste a raw security alert (a firewall log, phishing email, or IDS alert) and it extracts indicators of compromise, enriches them with live threat intelligence, maps the alert to MITRE ATT&CK, and produces a structured triage report with a severity rating and recommended response actions.

The design splits work between rules and the LLM on purpose. Rules handle what needs to be predictable and auditable: tool routing and threat scoring. The LLM handles what rules can't: catching obfuscated indicators, classifying the alert, and writing the analysis.

---

## ✨ Key Features

- **Two-pass IOC extraction**: regex for precise extraction of well-formed indicators, then an LLM pass to catch obfuscated or defanged ones (e.g. `hxxp://evil[.]com`).
- **Hallucination guard on LLM output**: every indicator the LLM adds is refanged, format-checked, and must literally appear in the original alert. Anything that fails is rejected and logged.
- **Type-based tool routing**: each IOC is routed to the tools that support it. Public IPs get VirusTotal + AbuseIPDB + geolocation, hashes and domains go to VirusTotal, emails skip network tools.
- **Internal IP protection**: private addresses (10.x, 172.16-31.x, 192.168.x, loopback, link-local) stay in the report but are never sent to external services.
- **Live threat intelligence**: real-time enrichment via VirusTotal, AbuseIPDB, and IP geolocation, with rate limiting for free-tier APIs.
- **RAG over MITRE ATT&CK**: semantic retrieval against a local ChromaDB store of 690+ techniques, with a relevance cutoff so weak matches never reach the report.
- **Deterministic threat scoring**: a rule-based 0-100 score, separate from the LLM, keeps severity explainable and consistent.
- **Graceful degradation**: rate limits, API failures, and malformed LLM responses are handled without crashing. If the LLM is unavailable, the pipeline falls back to regex-only extraction and a template report.
- **SOC dashboard**: a dark-themed Streamlit UI with severity badges, IOC detail panels, and MITRE technique cards.

---

## 🏗️ Architecture

The pipeline is a **LangGraph state machine** with four nodes and one conditional edge:

```
Raw Alert
   │
   ▼
[ parse ]   Regex pass + LLM pass, LLM output verified against the alert
   │
   ├── no IOCs found ──────────────┐
   ▼                               │
[ enrich ]  Route each IOC by type │ → VirusTotal / AbuseIPDB / GeoIP
   │         (internal IPs skipped) + deterministic 0-100 scoring
   ▼                               │
[ mitre ]  ◄───────────────────────┘
   │        RAG over MITRE ATT&CK (ChromaDB), weak matches dropped
   ▼
[ report ]  LLM writes a grounded analysis; severity comes from the score
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
│   └── orchestrator.py     # LangGraph state machine (the workflow)
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

**How is LLM extraction kept honest?** An LLM can invent indicators. Every IOC it adds must pass two checks: it has to match the format of its claimed type, and it has to appear in the original alert text (after refanging both). This grounds the LLM's output in the source.

**Why rule-based tool routing instead of LLM tool calling?** Which tools support which IOC type is a fixed fact, so rules route it reliably and every decision is auditable. The LLM is kept for the parts that need judgment.

**Why is scoring rule-based, not LLM-based?** Threat scores need to be consistent and explainable. The LLM writes the narrative; deterministic rules produce the number. They're computed independently, which also surfaces useful disagreements between qualitative and quantitative assessments.

**Why RAG for MITRE?** Asking an LLM to recall technique IDs from memory invites hallucination. Retrieving them from a curated vector store grounds the analysis in authoritative data. A distance cutoff (`MITRE_MAX_DISTANCE` in `config.py`) drops weak matches instead of always returning the top 3.

---

## 🗺️ Known Limitations & Roadmap

- **Prompt injection**: alert text is attacker-influenced and currently goes straight into LLM prompts. Next: clearly delimit untrusted input and validate outputs further.
- **Retries**: network errors are caught inside the API clients, so the retry decorator rarely triggers. Next: let transient errors and 429s propagate so retries fire.
- **Chunking**: each MITRE technique is embedded as one document, and the embedding model only reads roughly the first 256 tokens. Next: chunk long descriptions.
- **Sequential enrichment**: IOCs are enriched one at a time.
- **Evaluation**: no labeled eval set yet. Next: measure extraction precision/recall on labeled alerts.
- **LLM-driven routing**: tool routing is rule-based by design. A future branch could send ambiguous alerts to an LLM tool-calling path.

---

## 📄 License

MIT
