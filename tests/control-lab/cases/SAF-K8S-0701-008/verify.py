"""Verify both retrieved snapshots using the selected immutable record."""
from hashlib import sha256
import json
from pathlib import Path

record = json.loads(Path("/record/record.json").read_text())
artifact_digest = sha256(Path("/artifact/artifact.bin").read_bytes()).hexdigest()
dataset_digest = sha256(Path("/dataset/data.txt").read_bytes()).hexdigest()
mismatches = []
if artifact_digest != record["sha256"]:
    mismatches.append("artifact")
if dataset_digest != record["dataset_sha256"]:
    mismatches.append("dataset")
print(json.dumps({"verified": not mismatches, "dataset_revision": record["dataset_revision"],
                  "artifact_sha256": artifact_digest, "dataset_sha256": dataset_digest,
                  "record_version": record["record_version"], "mismatches": mismatches}))
raise SystemExit(1 if mismatches else 0)
