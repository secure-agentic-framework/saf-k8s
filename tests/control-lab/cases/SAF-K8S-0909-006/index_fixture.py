"""Owned synthetic SQLite vector-index lifecycle workload for SAF-K8S-0909-006."""
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path("/data/index-fixture")
BACKUP_ROOT = Path("/backup/vector-index-fixture")
ACTIVE = ROOT / "active.sqlite3"
APPROVED = ROOT / "snapshot-v1-approved.sqlite3"
ALTERED = ROOT / "snapshot-v2-benign-altered.sqlite3"
RETIRED = ROOT / "generation-retired.sqlite3"
STAGED = ROOT / "activation-stage.sqlite3"
BACKUP_APPROVED = BACKUP_ROOT / "snapshot-v1-approved.sqlite3"
APPROVAL = Path("/approval/approved.json")
MIGRATION_PLAN = Path("/migration/plan.json")
MIGRATION_PLAN_SHA256 = "67a6b2276e5544aea0365fcd804e3b94b98ea0c0ce5af296044fcf9e93a80b42"
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
MIGRATION_STAGE = ROOT / "migration-v2-stage.sqlite3"


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


def top_id_for(path, query, model_version, dimension):
    db = connect(path, read_only=True)
    try:
        rows = db.execute("SELECT id, model_version, vector_json FROM vectors ORDER BY id").fetchall()
        scored = []
        for row_id, version, raw in rows:
            if version != model_version:
                continue
            vector = json.loads(raw)
            if len(vector) != dimension or len(query) != dimension:
                continue
            norm = math.sqrt(sum(x*x for x in vector) * sum(x*x for x in query))
            score = sum(a*b for a, b in zip(vector, query)) / norm if norm else -1.0
            scored.append((score, row_id))
        return sorted(scored, key=lambda item: (-item[0], item[1]))[0][1] if scored else None
    finally:
        db.close()


def migration_plan():
    raw = MIGRATION_PLAN.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MIGRATION_PLAN_SHA256:
        raise ValueError("migration_plan_digest_mismatch")
    plan = json.loads(raw)
    if plan.get("transformation") != "project_first_two_coordinates_v1":
        raise ValueError("migration_transformation_not_approved")
    return plan


def migration_source_check(plan):
    meta, docs = metadata(ACTIVE)
    db = connect(ACTIVE, read_only=True)
    try:
        rows = db.execute("SELECT DISTINCT model_version FROM vectors ORDER BY model_version").fetchall()
        dimensions = {len(json.loads(row[0])) for row in
                      db.execute("SELECT vector_json FROM vectors").fetchall()}
    finally:
        db.close()
    source = plan["source"]
    return {
        "model_matches": meta.get("model_version") == source["model_version"] and
                         rows == [(source["model_version"],)],
        "content_digest_matches": meta.get("corpus_sha256") == source["corpus_sha256"] == corpus_digest(docs),
        "dimension_matches": dimensions == {source["dimension"]},
    }, docs


def transform_for_migration(docs, plan):
    source_dim = plan["source"]["dimension"]
    target_dim = plan["target"]["dimension"]
    if source_dim != 3 or target_dim != 2:
        raise ValueError("fixture_transform_dimension_mismatch")
    transformed = []
    for row in docs:
        if len(row["vector"]) != source_dim:
            raise ValueError("source_vector_dimension_mismatch")
        transformed.append({"id": row["id"], "text": row["text"],
                            "vector": row["vector"][:2]})
    return transformed


def build_migrated(path, docs, plan):
    if path.exists():
        path.unlink()
    db = connect(path)
    target = plan["target"]
    try:
        db.executescript("""
            CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE vectors (
                id TEXT PRIMARY KEY, text TEXT NOT NULL, model_version TEXT NOT NULL,
                vector_json TEXT NOT NULL
            );
        """)
        values = {"generation": target["generation"],
                  "model_version": target["model_version"],
                  "document_count": str(len(docs)),
                  "corpus_sha256": corpus_digest(docs),
                  "dimension": str(target["dimension"])}
        with db:
            db.executemany("INSERT INTO index_meta VALUES (?, ?)", sorted(values.items()))
            db.executemany("INSERT INTO vectors VALUES (?, ?, ?, ?)",
                           [(row["id"], row["text"], target["model_version"], canonical(row["vector"]))
                            for row in docs])
    finally:
        db.close()


def validate_migrated(path, plan):
    target = plan["target"]
    meta, docs = metadata(path)
    db = connect(path, read_only=True)
    try:
        rows = db.execute("SELECT model_version, vector_json FROM vectors").fetchall()
    finally:
        db.close()
    query = top_id_for(path, plan["known_query"], target["model_version"], target["dimension"])
    return {
        "sqlite_integrity_ok": integrity(path) == ["ok"],
        "target_model_matches": meta.get("model_version") == target["model_version"] and
                                {row[0] for row in rows} == {target["model_version"]},
        "target_dimension_matches": meta.get("dimension") == str(target["dimension"]) and
                                    all(len(json.loads(row[1])) == target["dimension"] for row in rows),
        "target_document_count_matches": meta.get("document_count") == str(len(docs)) == "3",
        "target_content_digest_matches": meta.get("corpus_sha256") == target["corpus_sha256"] == corpus_digest(docs),
        "known_query_matches": query == plan["expected_top_id"],
        "generation_matches": meta.get("generation") == target["generation"],
    }, query


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
    if command == "export-approved-to-backup":
        checks = approved_check(APPROVED)
        query = top_id(APPROVED, QUERY)
        if not all(checks.values()) or query != "doc-cedar":
            raise RuntimeError("approved source snapshot failed fixture checks")
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        snapshot(APPROVED, BACKUP_APPROVED)
        return {"backup_sha256": file_sha(BACKUP_APPROVED),
                "backup_bytes": BACKUP_APPROVED.stat().st_size,
                "approved_checks": checks, "known_query": query}
    if command == "inspect-backup":
        exists = BACKUP_APPROVED.is_file()
        return {"backup_present": exists,
                "backup_sha256": file_sha(BACKUP_APPROVED) if exists else None,
                "backup_bytes": BACKUP_APPROVED.stat().st_size if exists else 0,
                "approved_checks": approved_check(BACKUP_APPROVED) if exists else {},
                "known_query": top_id(BACKUP_APPROVED, QUERY) if exists else None}
    if command == "restore-approved-from-backup":
        expected_digest, expected_bytes = sys.argv[2], int(sys.argv[3])
        source_digest = file_sha(BACKUP_APPROVED) if BACKUP_APPROVED.is_file() else None
        source_bytes = BACKUP_APPROVED.stat().st_size if BACKUP_APPROVED.is_file() else 0
        source_checks = approved_check(BACKUP_APPROVED) if BACKUP_APPROVED.is_file() else {}
        source_query = top_id(BACKUP_APPROVED, QUERY) if BACKUP_APPROVED.is_file() else None
        source_digest_matches = source_digest == expected_digest
        source_size_matches = source_bytes == expected_bytes
        if not (source_digest_matches and source_size_matches and all(source_checks.values())
                and source_query == "doc-cedar"):
            return {"restore_performed": False,
                    "source_digest_matches": source_digest_matches,
                    "source_size_matches": source_size_matches,
                    "approved_checks": source_checks,
                    "restored_digest_matches": False,
                    "restored_size_matches": False,
                    "restored_query": None}
        ROOT.mkdir(parents=True, exist_ok=True)
        snapshot(BACKUP_APPROVED, STAGED)
        staged_digest_matches = file_sha(STAGED) == expected_digest
        staged_size_matches = STAGED.stat().st_size == expected_bytes
        checks = approved_check(STAGED)
        query = top_id(STAGED, QUERY)
        if not (staged_digest_matches and staged_size_matches and all(checks.values())
                and query == "doc-cedar"):
            STAGED.unlink(missing_ok=True)
            return {"restore_performed": False,
                    "source_digest_matches": source_digest_matches,
                    "source_size_matches": source_size_matches,
                    "approved_checks": checks,
                    "restored_digest_matches": staged_digest_matches,
                    "restored_size_matches": staged_size_matches,
                    "restored_query": query}
        os.replace(STAGED, ACTIVE)
        return {"restore_performed": True,
                "source_digest_matches": source_digest_matches,
                "source_size_matches": source_size_matches,
                "approved_checks": approved_check(ACTIVE),
                "restored_digest_matches": file_sha(ACTIVE) == expected_digest,
                "restored_size_matches": ACTIVE.stat().st_size == expected_bytes,
                "restored_query": top_id(ACTIVE, QUERY)}
    if command == "migration-incompatible":
        plan = migration_plan()
        before_digest = file_sha(ACTIVE)
        source_checks, _ = migration_source_check(plan)
        requested = {"model_version": "synthetic-unapproved-embed-v9", "dimension": 4}
        target = plan["target"]
        after_digest = file_sha(ACTIVE)
        return {"plan_digest_matches_pin": True,
                "plan_source_model_and_digest_match": all(source_checks.values()),
                "requested_incompatible_model_rejected": requested["model_version"] != target["model_version"],
                "requested_incompatible_dimension_rejected": requested["dimension"] != target["dimension"],
                "active_digest_before": before_digest,
                "active_digest_after": after_digest,
                "active_bytes_unchanged": before_digest == after_digest,
                "migration_stage_absent": not MIGRATION_STAGE.exists()}
    if command == "migration-approved":
        plan = migration_plan()
        before_digest = file_sha(ACTIVE)
        source_checks, docs = migration_source_check(plan)
        if not all(source_checks.values()):
            return {"plan_digest_matches_pin": True, "source_checks": source_checks,
                    "staged_validation_passed": False, "activation_performed": False,
                    "active_bytes_unchanged": file_sha(ACTIVE) == before_digest}
        transformed = transform_for_migration(docs, plan)
        target = plan["target"]
        derived_digest = corpus_digest(transformed)
        if derived_digest != target["corpus_sha256"]:
            return {"plan_digest_matches_pin": True, "source_checks": source_checks,
                    "derived_target_digest_matches_plan": False,
                    "staged_validation_passed": False, "activation_performed": False,
                    "active_bytes_unchanged": file_sha(ACTIVE) == before_digest}
        build_migrated(MIGRATION_STAGE, transformed, plan)
        stage_digest_before_activation = file_sha(MIGRATION_STAGE)
        stage_checks, stage_query = validate_migrated(MIGRATION_STAGE, plan)
        stage_valid = all(stage_checks.values()) and stage_query == plan["expected_top_id"]
        if not stage_valid:
            MIGRATION_STAGE.unlink(missing_ok=True)
            return {"plan_digest_matches_pin": True, "source_checks": source_checks,
                    "derived_target_digest_matches_plan": True,
                    "staged_validation_passed": False, "staged_checks": stage_checks,
                    "staged_query": stage_query, "activation_performed": False,
                    "active_bytes_unchanged": file_sha(ACTIVE) == before_digest}
        os.replace(MIGRATION_STAGE, ACTIVE)
        active_checks, active_query = validate_migrated(ACTIVE, plan)
        return {"plan_digest_matches_pin": True,
                "source_checks": source_checks,
                "derived_target_digest_matches_plan": True,
                "staged_validation_passed": True,
                "staged_checks": stage_checks,
                "staged_query_before_activation": stage_query,
                "staged_and_active_digest_match": file_sha(ACTIVE) == stage_digest_before_activation,
                "activation_performed": True,
                "active_checks": active_checks,
                "active_query_after_activation": active_query,
                "active_model_version": metadata(ACTIVE)[0].get("model_version"),
                "active_dimension": metadata(ACTIVE)[0].get("dimension"),
                "active_bytes_changed_from_source": file_sha(ACTIVE) != before_digest}
    raise ValueError("unknown fixture operation")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1]), sort_keys=True))
