"""Deterministic JSON-only fixture evaluator; no model loader or dynamic code."""
import hashlib
import json
from pathlib import Path

fixture = json.loads(Path("/fixture/fixture.json").read_text())
allowed = set(fixture["permitted_operations"])
if fixture["schema"] != "saf-toy-behavior-v1" or allowed != {"classify_text"}:
    raise SystemExit("fixture schema or operation set rejected")
if len(fixture["records"]) != 2:
    raise SystemExit("fixture record count rejected")
if [row.get("candidate_id") for row in fixture["records"]] != [
        "toy-clean-v1", "toy-reject-v1"]:
    raise SystemExit("candidate set rejected")

marker_outputs = {
    "fixture benign sample": "safe",
    "fixture synthetic rejection sample": "unsafe",
}
results = []
trace = []
for record in fixture["records"]:
    if record["operation"] not in allowed or set(record) != {
            "candidate_id", "operation", "input", "expected_label"}:
        raise SystemExit("record outside bounded operation schema")
    if set(record["input"]) != {"text"} or not isinstance(record["input"]["text"], str):
        raise SystemExit("input outside bounded JSON schema")
    text = record["input"]["text"]
    if text not in marker_outputs:
        raise SystemExit("input outside the two fixed inert behavior markers")
    observed_label = marker_outputs[text]
    trace.append({"candidate_id": record["candidate_id"],
                  "input_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "output_label": observed_label})
    passed = observed_label == record["expected_label"]
    results.append({
        "candidate_id": record["candidate_id"],
        "operation": record["operation"],
        "expected_label": record["expected_label"],
        "observed_label": observed_label,
        "outcome": "pass" if passed else "fail",
        "reason": "expected_behavior" if passed else "behavioral_policy_violation",
    })

canonical = json.dumps({"evaluator": "toy-evaluator-v1", "records": results,
                        "behavior_trace": trace},
                       sort_keys=True, separators=(",", ":")).encode()
report = {"evaluator": "toy-evaluator-v1", "records": results,
          "behavior_trace": trace,
          "evaluation_sha256": hashlib.sha256(canonical).hexdigest()}
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
