"""
MITRE ATT&CK Search Tool
========================
Semantic search over the local MITRE ATT&CK vector store.

Given alert text or enrichment context, this returns the most
relevant attack techniques. This is the RAG (retrieval-augmented
generation) component of the project: instead of asking the LLM to
recall MITRE techniques from memory (unreliable), we retrieve them
from a curated knowledge base and ground the analysis in real data.
"""

from typing import Optional

import chromadb
from chromadb.utils import embedding_functions

from config import (
    CHROMA_PERSIST_DIR,
    CHROMA_COLLECTION_NAME,
    EMBEDDING_MODEL,
    MITRE_MAX_DISTANCE,
)

# Module-level cache so we don't reload the model on every call
_collection = None


def _get_collection():
    """Lazily load the ChromaDB collection (cached after first call)."""
    global _collection
    if _collection is None:
        client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL
        )
        _collection = client.get_collection(
            name=CHROMA_COLLECTION_NAME,
            embedding_function=embed_fn,
        )
    return _collection


def search_techniques(
    query: str,
    top_k: int = 3,
    max_distance: Optional[float] = MITRE_MAX_DISTANCE,
) -> list[dict]:
    """
    Find the MITRE ATT&CK techniques most relevant to the query text.

    Args:
        query: Alert text, IOC context, or threat description
        top_k: Maximum number of techniques to return
        max_distance: Drop matches with a distance above this
            (weak matches). None disables the cutoff.

    Returns:
        List of dicts with technique id, name, tactics, description,
        and a relevance distance (lower = more relevant).
    """
    try:
        collection = _get_collection()
    except Exception as e:
        # Knowledge base not loaded yet
        return [{
            "error": f"MITRE knowledge base unavailable: {e}. "
                     f"Run 'python -m data.load_mitre' first."
        }]

    results = collection.query(
        query_texts=[query],
        n_results=top_k,
    )

    techniques = []
    if results and results.get("ids") and results["ids"][0]:
        for i in range(len(results["ids"][0])):
            meta = results["metadatas"][0][i]
            doc = results["documents"][0][i]
            distance = results["distances"][0][i] if results.get("distances") else None

            # Relevance cutoff: skip weak matches instead of always
            # returning top_k, so unrelated techniques never reach the report
            if (max_distance is not None and distance is not None
                    and distance > max_distance):
                continue

            # Truncate description for readability
            description = doc.split(". ", 1)[-1] if ". " in doc else doc
            if len(description) > 300:
                description = description[:300] + "..."

            techniques.append({
                "technique_id": meta.get("technique_id", ""),
                "name": meta.get("name", ""),
                "tactics": meta.get("tactics", ""),
                "description": description,
                "relevance_distance": round(distance, 4) if distance is not None else None,
            })

    return techniques


# -- Quick test --
if __name__ == "__main__":
    print("Testing MITRE ATT&CK search...")
    print("=" * 60)

    test_queries = [
        "outbound command and control communication over HTTPS",
        "phishing email with malicious link",
        "malware establishing persistence via registry",
    ]

    for q in test_queries:
        print(f"\nQuery: '{q}'")
        print("-" * 60)
        # Cutoff disabled here so you can see raw distances for calibration
        results = search_techniques(q, top_k=3, max_distance=None)

        if results and "error" in results[0]:
            print(f"  {results[0]['error']}")
            break

        for r in results:
            print(f"  [{r['technique_id']}] {r['name']}")
            print(f"     Tactics: {r['tactics']}")
            print(f"     Relevance: {r['relevance_distance']}")

    print("\n" + "=" * 60)
    print("Done.")
