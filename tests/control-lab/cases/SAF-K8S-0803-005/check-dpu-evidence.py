"""Classify modeled device recovery evidence for an isolated lab case."""

import json
from pathlib import Path

evidence = json.loads(Path("/fixture/observations.json").read_text())
result = {}
for name, row in evidence.items():
    measured = row["signed_record"]
    if row["signature_verified"] is not True:
        outcome = "invalid-signature"
    elif measured["device"] != row["expected_device"]:
        outcome = "wrong-device"
    elif measured["event_generation"] < row["minimum_generation"]:
        outcome = "stale-evidence"
    elif row["independent_boot_observation"] != "reviewed" or measured["boot"] != "fixture-verified":
        outcome = "boot-evidence-missing"
    elif measured["revision"] != row["expected_revision"]:
        outcome = "unexpected-revision"
    else:
        outcome = "consistent-fixture"
    result[name] = outcome
print(json.dumps(result, sort_keys=True))
