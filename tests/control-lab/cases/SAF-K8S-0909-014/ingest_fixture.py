"""Tiny synthetic signed-document ingestion and persisted retrieval workload."""
import hashlib
import json
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

SOURCE_ID = "synthetic://field-notes/orchid-river/42"
ISSUER = "Synthetic Data Steward"
KEY_ID = "saf-rag-lab-ecdsa-v1"
VOCABULARY = ("orchid", "river", "quiet", "garden", "signal", "blue", "green")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def approved(document, manifest_path, source_id):
    raw_manifest = manifest_path.read_bytes()
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "manifest_invalid"
    if (manifest.get("schema") != "saf-rag-approval/1"
            or manifest.get("issuer") != ISSUER or manifest.get("key_id") != KEY_ID
            or manifest.get("source_id") != source_id or source_id != SOURCE_ID):
        return None, "approval_binding_mismatch"
    if manifest.get("document_sha256") != sha256(document):
        return None, "document_digest_mismatch"
    now = datetime.now(timezone.utc)
    try:
        issued = datetime.fromisoformat(manifest["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None or not issued <= now <= expires:
            return None, "approval_out_of_window"
    except (KeyError, TypeError, ValueError):
        return None, "approval_time_invalid"
    return manifest, None


def chunks_for(document):
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError:
        return None
    header, _, body = text.partition("\n\n")
    if header != "SYNTH-RAG/1\nORCHID RIVER FIELD NOTE":
        return None
    chunks = [line.strip() for line in body.splitlines() if line.strip()]
    if len(chunks) != 2 or any(len(line) > 160 for line in chunks):
        return None
    return chunks


def vector(text):
    words = re.findall(r"[a-z]+", text.lower())
    return [words.count(word) for word in VOCABULARY]


def retrieve(index_path, query):
    index = json.loads(index_path.read_text())
    q = vector(query)
    scored = []
    for item in index["vectors"]:
        score = sum(left * right for left, right in zip(q, item["vector"]))
        scored.append((score, item["chunk_id"], item["chunk_sha256"]))
    score, chunk_id, chunk_digest = max(scored)
    chunks = json.loads((index_path.parent / "chunks.json").read_text())
    match = next(item for item in chunks if item["chunk_id"] == chunk_id)
    if not match.get("text"):
        raise ValueError("Persisted retrieval chunk is empty")
    return {"chunk_id": chunk_id, "score": score, "chunk_sha256": chunk_digest}


def observe(store_path):
    store = Path(store_path)
    files = sorted(path.name for path in store.iterdir() if path.is_file())
    if files:
        chunks = json.loads((store / "chunks.json").read_text())
        index = json.loads((store / "vector-index.json").read_text())
        receipt = json.loads((store / "source-receipt.json").read_text())
        result = retrieve(store / "vector-index.json", "orchid archive")
    else:
        chunks, index, receipt, result = [], {}, {}, {}
    print(json.dumps({"files": files, "chunks": chunks, "index": index,
                      "receipt": receipt, "retrieval": result}, sort_keys=True))


def main(mode, doc_path, manifest_path, signature_path, store_path):
    document = Path(doc_path).read_bytes()
    store = Path(store_path)
    if mode == "governed":
        manifest, reason = approved(document, Path(manifest_path), SOURCE_ID)
        if reason:
            print(json.dumps({"event": "document_rejected", "reason": reason,
                              "source_id": SOURCE_ID, "document_sha256": sha256(document),
                              "signature_verified": True,
                              "chunk_calls": 0, "writes": 0}, sort_keys=True))
            return
    else:
        manifest = None

    chunks = chunks_for(document)
    if chunks is None:
        print(json.dumps({"event": "document_rejected", "reason": "format_invalid",
                          "chunk_calls": 1, "writes": 0}, sort_keys=True))
        return
    rows = [{"chunk_id": f"chunk-{number:03d}", "text": text,
             "chunk_sha256": sha256(text.encode("utf-8"))}
            for number, text in enumerate(chunks, 1)]
    index = {"schema": "saf-toy-vector-index/1", "source_id": SOURCE_ID,
             "vocabulary": list(VOCABULARY),
             "vectors": [{"chunk_id": row["chunk_id"], "chunk_sha256": row["chunk_sha256"],
                          "vector": vector(row["text"])} for row in rows]}
    receipt = {"schema": "saf-source-receipt/1", "source_id": SOURCE_ID,
               "document_sha256": sha256(document), "retrieved_at": utc_now(),
               "signature_verified": manifest is not None,
               "chunk_digests": [{"chunk_id": row["chunk_id"],
                                  "chunk_sha256": row["chunk_sha256"]} for row in rows],
               "vector_index_sha256": None,
               "issuer": manifest.get("issuer") if manifest else None,
               "key_id": manifest.get("key_id") if manifest else None,
               "manifest_sha256": sha256(Path(manifest_path).read_bytes()) if manifest else None,
               "signature_sha256": sha256(Path(signature_path).read_bytes()) if manifest else None,
               "issued_at": manifest.get("issued_at") if manifest else None,
               "expires_at": manifest.get("expires_at") if manifest else None}
    chunks_bytes = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    index_bytes = json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["vector_index_sha256"] = sha256(index_bytes)
    receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # Each published artifact is written only after governed verification and chunk checks.
    (store / "chunks.json").write_bytes(chunks_bytes)
    (store / "vector-index.json").write_bytes(index_bytes)
    (store / "source-receipt.json").write_bytes(receipt_bytes)
    if manifest is not None:
        (store / "approval-manifest.json").write_bytes(Path(manifest_path).read_bytes())
        (store / "approval.sig").write_bytes(Path(signature_path).read_bytes())
    query = "orchid archive"
    result = retrieve(store / "vector-index.json", query)
    print(json.dumps({"event": "ingested", "source_id": SOURCE_ID,
                      "document_sha256": sha256(document), "signature_verified": manifest is not None,
                      "chunk_calls": 1, "chunk_count": len(rows),
                      "chunk_ids": [row["chunk_id"] for row in rows],
                      "vectors_persisted": len(index["vectors"]),
                      "writes": 5 if manifest is not None else 3,
                      "receipt_persisted": True, "retrieval": result}, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1] == "observe":
        observe(sys.argv[2])
    else:
        main(*sys.argv[1:])
