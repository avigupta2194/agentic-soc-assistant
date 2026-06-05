"""
MITRE ATT&CK Data Loader
========================
Downloads the official MITRE ATT&CK Enterprise dataset and loads
each technique into a local ChromaDB vector store.

The data comes from the MITRE CTI GitHub repo (free, public, no key).
We embed each technique's name + description using a local
sentence-transformers model so the agent can semantically search
for techniques relevant to an alert.

Run once:  python -m data.load_mitre
"""

import json
import requests
import chromadb
from chromadb.utils import embedding_functions

from config import (
    CHROMA_PERSIST_DIR,
    CHROMA_COLLECTION_NAME,
    EMBEDDING_MODEL,
)

# Official MITRE ATT&CK Enterprise data (STIX 2.1 bundle, public)
MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_mitre_data() -> dict:
    """Download the MITRE ATT&CK Enterprise STIX bundle."""
    print("  Downloading MITRE ATT&CK data (~30 MB, may take a minute)...")
    resp = requests.get(MITRE_ENTERPRISE_URL, timeout=120)
    resp.raise_for_status()
    print("  Download complete.")
    return resp.json()


def extract_techniques(stix_data: dict) -> list[dict]:
    """
    Pull attack techniques out of the STIX bundle.

    A technique in STIX is an 'attack-pattern' object. We keep the
    technique ID (like T1071), name, description, and tactic(s).
    """
    techniques = []

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Skip deprecated/revoked techniques
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # The technique ID (e.g., T1071) lives in external_references
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        # Tactics are stored as kill_chain_phases
        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": ", ".join(tactics),
        })

    return techniques


def load_into_chroma(techniques: list[dict]) -> None:
    """Embed techniques and store them in a local ChromaDB collection."""
    print(f"  Loading {len(techniques)} techniques into ChromaDB...")

    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

    # Use a local embedding model (free, runs on CPU)
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    # Reset collection if it already exists (fresh load each run)
    try:
        client.delete_collection(CHROMA_COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(
        name=CHROMA_COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "MITRE ATT&CK Enterprise techniques"},
    )

    # Build the documents we embed: name + description gives the best
    # semantic match against alert text
    documents = []
    metadatas = []
    ids = []

    for t in techniques:
        doc_text = f"{t['name']}. {t['description']}"
        documents.append(doc_text)
        metadatas.append({
            "technique_id": t["id"],
            "name": t["name"],
            "tactics": t["tactics"],
        })
        ids.append(t["id"])

    # Add in batches (ChromaDB handles embedding internally)
    BATCH = 100
    for i in range(0, len(documents), BATCH):
        collection.add(
            documents=documents[i:i + BATCH],
            metadatas=metadatas[i:i + BATCH],
            ids=ids[i:i + BATCH],
        )
        print(f"    Embedded {min(i + BATCH, len(documents))}/{len(documents)}")

    print(f"  Done. Collection '{CHROMA_COLLECTION_NAME}' now has "
          f"{collection.count()} techniques.")


def main():
    print("=" * 60)
    print("MITRE ATT&CK LOADER")
    print("=" * 60)

    stix_data = download_mitre_data()
    techniques = extract_techniques(stix_data)
    print(f"  Extracted {len(techniques)} active techniques.")

    load_into_chroma(techniques)

    print("=" * 60)
    print("MITRE ATT&CK knowledge base is ready.")
    print("=" * 60)


if __name__ == "__main__":
    main()
