"""Validate byte identity of an inert, synthetic text fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


ROOT = Path("/fixture")
EXPECTED_APPROVAL = {
    "approval_id": "approval-fixture-1005-015-001",
    "approver": "synthetic-reviewer-01",
    "decision": "approved",
    "operation": "reconstruct",
    "artifact_id": "fixture-1005-015-001",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(decision, **details):
    print(json.dumps({"decision": decision, **details}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, choices=("changed.txt", "reconstructed.txt"))
    parser.add_argument("--mode", required=True, choices=("bypass", "enforce"))
    args = parser.parse_args()

    candidate = ROOT / args.candidate
    observed = digest(candidate)
    if args.mode == "bypass":
        emit("accepted_without_integrity_check", candidate_sha256=observed)
        return 0

    record = json.loads((ROOT / "integrity-record.json").read_text(encoding="utf-8"))
    approval = json.loads((ROOT / "approval.json").read_text(encoding="utf-8"))
    baseline = digest(ROOT / "pre-incident.txt")
    expected = record["sha256"]
    approved = (all(approval.get(key) == value for key, value in EXPECTED_APPROVAL.items())
                and approval.get("approved_sha256") == expected)
    record_valid = (record.get("record_id") == "pre-incident-record-fixture-1005-015-001"
                    and record.get("artifact_id") == "fixture-1005-015-001"
                    and record.get("source") == "synthetic-pre-incident-baseline")
    if not record_valid or baseline != expected or expected != os.environ["EXPECTED_BASELINE"] or not approved:
        emit("blocked", reason="baseline_or_approval_invalid", candidate_sha256=observed,
             baseline_sha256=baseline, recorded_sha256=expected, approval_valid=approved)
        return 1
    if observed != expected:
        emit("blocked", reason="candidate_digest_mismatch", candidate_sha256=observed,
             baseline_sha256=expected, approval_valid=True)
        return 1

    emit("reconstruction_validated", candidate_sha256=observed,
         baseline_sha256=expected, approval_id=approval["approval_id"], approval_valid=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
