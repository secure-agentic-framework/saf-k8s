"""Owned synthetic SQLite vector-index lifecycle workload for SAF-K8S-0909-006."""
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path("/data/index-fixture")
ACTIVE = ROOT / "active.sqlite3"
APPROVED = ROOT / "snapshot-v1-approved.sqlite3"
ALTERED = ROOT / "snapshot-v2-benign-altered.sqlite3"
RETIRED = ROOT / "generation-retired.sqlite3"
STAGED = ROOT / "activation-stage.sqlite3"
APPROVAL = Path("/approval/approved.json")
MODEL = "synthetic-hash-embed-v1"
APPROVED_DOCS = [
    {"id": "doc-cedar", "text": "cedar fixture token is amber", "vector": [1.0, 0.0, 0.0]},
    {"id": "doc-maple", "text": "maple fixture token is blue", "vector": [0.0, 1.0, 0.0]},
    {"id": "doc-birch", "text": "birch fixture token is green", "vector": [0.0, 0.0, 1.0]},
]
ALTERED_DOCS = [
    {"id": "doc-cedar", "text": "cedar fixture token is violet", "vector": [-1.0, 0.0, 0.0]},
    {"id": "doc-maple", "text": "maple fixture token is blue", "vector": [0.0, 1.0, 0.0]},
    {"id": "doc-birch", "text": "birch fixture token is green", "vector": [0.0, 0.0, 1.0]},
]
QUERY = [1.0, 0.0, 0.0]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def corpus_digest(docs):
    return hashlib.sha256(canonical(sorted(docs, key=lambda row: row["id"])).encode()).hexdigest()


def connect(path, *, read_only=False):
    if read_only:
        return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    db = sqlite3.connect(str(path))
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def build(path, docs, generation):
    if path.exists():
        path.unlink()
    db = connect(path)
    try:
        db.executescript("""
            CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE vectors (
                id TEXT PRIMARY KEY, text TEXT NOT NULL, model_version TEXT NOT NULL,
                vector_json TEXT NOT NULL
            );
        """)
        values = {"generation": generation, "model_version": MODEL,
                  "document_count": str(len(docs)), "corpus_sha256": corpus_digest(docs)}
        with db:
            db.executemany("INSERT INTO index_meta VALUES (?, ?)", sorted(values.items()))
            db.executemany("INSERT INTO vectors VALUES (?, ?, ?, ?)",
                           [(d["id"], d["text"], MODEL, canonical(d["vector"])) for d in docs])
    finally:
        db.close()


def snapshot(src, dst):
    if dst.exists():
        dst.unlink()
    source = connect(src, read_only=True)
    target = connect(dst)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def integrity(path):
    db = connect(path, read_only=True)
    try:
        return [r[0] for r in db.execute("PRAGMA integrity_check")]
    finally:
        db.close()


def metadata(path):
    db = connect(path, read_only=True)
    try:
        meta = dict(db.execute("SELECT key, value FROM index_meta"))
        rows = db.execute("SELECT id, text, model_version, vector_json FROM vectors ORDER BY id").fetchall()
        docs = [{"id": row[0], "text": row[1], "vector": json.loads(row[3])} for row in rows]
        return meta, docs
    finally:
        db.close()


def top_id(path, query):
    db = connect(path, read_only=True)
    try:
        rows = db.execute("SELECT id, model_version, vector_json FROM vectors").fetchall()
        scored = []
        for row_id, version, raw in rows:
            if version != MODEL:
                continue
            vector = json.loads(raw)
            norm = math.sqrt(sum(x*x for x in vector) * sum(x*x for x in query))
            score = sum(a*b for a, b in zip(vector, query)) / norm if norm else -1.0
            scored.append((score, row_id))
        return sorted(scored, key=lambda item: (-item[0], item[1]))[0][1] if scored else None
    finally:
        db.close()


def approved_check(path):
    approved = json.loads(APPROVAL.read_text())
    meta, docs = metadata(path)
    db = connect(path, read_only=True)
    try:
        row_versions = [r[0] for r in db.execute("SELECT DISTINCT model_version FROM vectors ORDER BY model_version")]
    finally:
        db.close()
    return {
        "sqlite_integrity_ok": integrity(path) == ["ok"],
        "approved_generation": meta.get("generation") == approved["generation"],
        "approved_model_version": meta.get("model_version") == approved["model_version"],
        "approved_document_count": meta.get("document_count") == str(approved["document_count"]),
        "approved_corpus_digest": meta.get("corpus_sha256") == approved["corpus_sha256"]
                                  == corpus_digest(docs),
        "approved_documents_match": sorted(docs, key=lambda row: row["id"])
                                     == sorted(approved["documents"], key=lambda row: row["id"]),
        "all_vector_rows_use_approved_model": row_versions == [approved["model_version"]],
    }


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    ROOT.mkdir(parents=True, exist_ok=True)
    if command == "prepare":
        build(ACTIVE, APPROVED_DOCS, "v1-approved")
        snapshot(ACTIVE, APPROVED)
        build(ALTERED, ALTERED_DOCS, "v2-benign-altered")
        # A third, approved synthetic generation is retained solely for scoped retirement.
        build(RETIRED, APPROVED_DOCS, "v0-retired")
        return {"active_initial": top_id(ACTIVE, QUERY), "approved_snapshot": file_sha(APPROVED),
                "altered_snapshot": file_sha(ALTERED), "retired_generation_present": RETIRED.exists()}
    if command == "inspect-retained":
        return {"approved_snapshot_retained": APPROVED.is_file() and all(approved_check(APPROVED).values()),
                "known_query_retained": top_id(ACTIVE, QUERY) == "doc-cedar"}
    if command == "red":
        before = {"active_generation": metadata(ACTIVE)[0].get("generation"),
                  "active_query": top_id(ACTIVE, QUERY)}
        # This intentionally models an unsafe snapshot activation, confined to this fixture.
        snapshot(ALTERED, STAGED)
        os.replace(STAGED, ACTIVE)
        after = {"active_generation": metadata(ACTIVE)[0].get("generation"),
                 "active_query": top_id(ACTIVE, QUERY)}
        return {"unsafe_activation_occurred": before != after,
                "altered_snapshot_query_wrong": after["active_query"] != "doc-cedar",
                "integrity_still_passes": integrity(ACTIVE) == ["ok"],
                "before": before, "after": after}
    if command == "guard-altered":
        before_bytes = file_sha(ACTIVE)
        before_query = top_id(ACTIVE, QUERY)
        snapshot(ALTERED, STAGED)
        stage_checks = approved_check(STAGED)
        stage_query = top_id(STAGED, QUERY)
        approved = json.loads(APPROVAL.read_text())
        rejected = not all(stage_checks.values()) or stage_query != approved["expected_top_id"]
        if rejected:
            STAGED.unlink()
        else:
            os.replace(STAGED, ACTIVE)
        return {"altered_snapshot_integrity_ok": integrity(ALTERED) == ["ok"],
                "approved_metadata_rejects_altered_snapshot": not all(stage_checks.values()),
                "observed_query_rejects_altered_snapshot": stage_query != approved["expected_top_id"],
                "activation_blocked": rejected,
                "active_file_unchanged": file_sha(ACTIVE) == before_bytes,
                "live_query_preserved": top_id(ACTIVE, QUERY) == before_query == approved["expected_top_id"],
                "staged_checks": stage_checks, "staged_query": stage_query}
    if command == "restore-approved":
        snapshot(APPROVED, STAGED)
        checks = approved_check(STAGED)
        observed = top_id(STAGED, QUERY)
        if not all(checks.values()) or observed != "doc-cedar":
            STAGED.unlink(missing_ok=True)
            return {"activation_blocked": True, "approved_checks": checks, "staged_query": observed}
        os.replace(STAGED, ACTIVE)
        return {"activation_blocked": False, "approved_checks": approved_check(ACTIVE),
                "restored_query": top_id(ACTIVE, QUERY), "active_generation": metadata(ACTIVE)[0]["generation"]}
    if command == "rebuild-approved":
        approved = json.loads(APPROVAL.read_text())
        if approved["model_version"] != MODEL:
            return {"activation_blocked": True, "reason": "approved model is incompatible with this fixture builder"}
        build(STAGED, approved["documents"], approved["generation"])
        staged_checks = approved_check(STAGED)
        staged_query = top_id(STAGED, approved["known_query"])
        if not all(staged_checks.values()) or staged_query != approved["expected_top_id"]:
            STAGED.unlink(missing_ok=True)
            return {"activation_blocked": True, "staged_checks": staged_checks, "staged_query": staged_query}
        os.replace(STAGED, ACTIVE)
        return {"activation_blocked": False, "staged_checks": staged_checks,
                "active_checks": approved_check(ACTIVE), "observed_query": top_id(ACTIVE, approved["known_query"]),
                "active_generation": metadata(ACTIVE)[0]["generation"], "model_version": MODEL}
    if command == "retire":
        # This exact fixture-owned file is closed before unlink and is never a mounted volume.
        if RETIRED.parent != ROOT or RETIRED.name != "generation-retired.sqlite3":
            raise RuntimeError("retirement target escaped the fixture-owned path")
        before = RETIRED.exists()
        if before:
            RETIRED.unlink()
        return {"fixture_generation_existed": before, "fixture_generation_absent_after_unlink": not RETIRED.exists(),
                "active_generation_preserved": metadata(ACTIVE)[0]["generation"] == "v1-approved",
                "active_query": top_id(ACTIVE, QUERY)}
    raise ValueError("unknown fixture operation")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1]), sort_keys=True))
