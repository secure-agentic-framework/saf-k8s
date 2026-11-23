"""Consume only fixed invented training data and emit minimal access records."""
import json
import os
from pathlib import Path
import sys

from data_fixture import APPROVED, BAD, DIRECT_IDENTIFIER_FIELDS, canonical, classify, digest, receipt, sanitize

ROOT = Path("/store")
OUTPUT = ROOT / "approved" / "training.json"


def emit(row):
    print(canonical(row), flush=True)


def write(path, data):
    path.write_text(canonical(data) + "\n")
    path.chmod(0o640)


def baseline():
    for dataset in (APPROVED, BAD):
        write(ROOT / "baseline" / (dataset["dataset_id"] + ".json"), dataset)
    emit({"baseline_published_both": True})


def process():
    output = sanitize(APPROVED)
    write(OUTPUT, output)
    write(ROOT / "held" / "receipt.json", receipt(BAD, sanitize(BAD)))
    emit({"approved": receipt(APPROVED, output), "held": classify(BAD)})


def inspect():
    excluded = {row[k] for src in (APPROVED, BAD) for row in src["rows"]
                for k in DIRECT_IDENTIFIER_FIELDS}
    baseline = ROOT / "baseline"
    approved_raw = json.loads((baseline / (APPROVED["dataset_id"] + ".json")).read_text())
    held_raw = json.loads((baseline / (BAD["dataset_id"] + ".json")).read_text())
    value = OUTPUT.read_text()
    retained = json.loads(value)
    held = ROOT / "held"
    checks = {
        "unrestricted_baseline_retained_direct_identifiers": any(
            field in row for row in approved_raw["rows"] for field in DIRECT_IDENTIFIER_FIELDS
        ),
        "unrestricted_baseline_published_held_version": held_raw["dataset_id"] == BAD["dataset_id"],
        "approved_durable_output_matches_minimized_contract": retained == sanitize(APPROVED)
        and all(not any(k in row for k in DIRECT_IDENTIFIER_FIELDS) for row in retained["rows"])
        and all(item not in value for item in excluded),
        "held_dataset_has_disposition_only": sorted(path.name for path in held.iterdir()) == ["receipt.json"]
        and json.loads((held / "receipt.json").read_text()) == receipt(BAD, None),
        "approved_sha256": digest(retained),
    }
    emit(checks)


def read():
    event = {"event": "training-data-read", "dataset_id": APPROVED["dataset_id"],
             "principal": "system:serviceaccount:" + os.environ["POD_NAMESPACE"] + ":" + os.environ["POD_ACCOUNT"],
             "uid": os.getuid()}
    try:
        value = json.loads(OUTPUT.read_text())
    except PermissionError:
        emit({**event, "decision": "denied", "reason": "permission-denied"})
        return
    emit({**event, "decision": "allowed", "output_sha256": digest(value), "row_count": len(value["rows"])})


if __name__ == "__main__":
    {"baseline": baseline, "process": process, "inspect": inspect, "read": read}[sys.argv[1]]()
