"""Worker and durable-state consumer executed by isolated Kubernetes Jobs."""
import json
import os
from pathlib import Path
import sys

from feature_fixture import CUTOFF, EXPECTED_OUTPUT, RECORDS, validate_and_transform


ROOT = Path("/published")


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def produce(case_name, governed=True):
    record = RECORDS[case_name]
    if governed:
        output, reason = validate_and_transform(record)
    else:
        output, reason = record, None
    if reason:
        emit({"event": "publication-decision", "case": case_name,
              "decision": "rejected", "reason": reason, "persisted": False})
        raise SystemExit(2)
    directory = ROOT if governed else ROOT / "baseline"
    directory.mkdir(exist_ok=True)
    destination = directory / f"{case_name}.json"
    temporary = directory / f".{case_name}.tmp"
    temporary.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(temporary, destination)
    emit({"event": "publication-decision", "case": case_name,
          "decision": "published", "reason": None, "persisted": True})


def consume():
    actual = sorted(path.name for path in ROOT.glob("*.json"))
    expected = ["valid.json"]
    valid_bytes = (ROOT / "valid.json").read_text() if actual == expected else ""
    decoded = json.loads(valid_bytes) if valid_bytes else None
    output_clean = (isinstance(decoded, dict) and decoded == EXPECTED_OUTPUT["valid"]
                    and "subject_id" not in decoded
                    and "row_id" not in decoded
                    and not any("subject" in key for key in decoded.get("features", {})))
    result = {"event": "consumer-observation", "expected_files": expected,
              "observed_files": actual, "valid_output_matches_contract": output_clean,
              "candidate_outputs_absent": all(name not in actual for name in
                                               ("direct-id.json", "target-derived.json",
                                                "after-cutoff.json")),
              "temporal_cutoff": CUTOFF}

    emit(result)
    if not all((result["observed_files"] == expected, output_clean,
                result["candidate_outputs_absent"])):
        raise SystemExit(3)

def inspect_baseline():
    rows = {name: json.loads((ROOT / "baseline" / f"{name}.json").read_text())
            for name in ("direct-id", "target-derived", "after-cutoff")}
    emit({
        "baseline_retained_identifier_feature": rows["direct-id"]["features"]["subject_id"]
        == rows["direct-id"]["subject_id"],
        "baseline_retained_label_derived_feature": rows["target-derived"]["features"]["target_code"] == 1,
        "baseline_retained_future_record": rows["after-cutoff"]["event_time"] > CUTOFF,
    })



if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "produce" and sys.argv[2] in RECORDS:
        produce(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "baseline" and sys.argv[2] in RECORDS:
        produce(sys.argv[2], governed=False)
    elif len(sys.argv) == 2 and sys.argv[1] == "consume":
        consume()
    elif len(sys.argv) == 2 and sys.argv[1] == "inspect-baseline":
        inspect_baseline()
    else:
        raise SystemExit("usage: pipeline_fixture.py produce CASE | consume")
