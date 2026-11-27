"""Deterministic JSON-only fixture evaluator; no model loader or dynamic code."""
import hashlib
import json
from pathlib import Path

fixture = json.loads(Path("/fixture/fixture.json").read_text())
allowed = set(fixture["permitted_operations"])
if fixture["schema"] != "saf-toy-behavior-v1" or allowed != {"classify_text"}:
    raise SystemExit("fixture schema or operation set rejected")
if len(fixture["records"]) != 3:
    raise SystemExit("fixture record count rejected")
if [row.get("candidate_id") for row in fixture["records"]] != [
        "toy-clean-v1", "toy-reject-v1", "toy-inconclusive-v1"]:
    raise SystemExit("candidate set rejected")

marker_outputs = {
    "fixture benign sample": "safe",
    "fixture synthetic rejection sample": "unsafe",
    "fixture review-needed sample": "inconclusive",
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
    if passed:
        outcome, reason = "pass", "expected_behavior"
    elif observed_label == "inconclusive":
        outcome, reason = "inconclusive", "insufficient_evidence"
    else:
        outcome, reason = "fail", "behavioral_policy_violation"
    results.append({
        "candidate_id": record["candidate_id"],
        "operation": record["operation"],
        "expected_label": record["expected_label"],
        "observed_label": observed_label,
        "outcome": outcome,
        "reason": reason,
    })

canonical = json.dumps({"evaluator": "toy-evaluator-v1", "records": results,
                        "behavior_trace": trace},
                       sort_keys=True, separators=(",", ":")).encode()
report = {"evaluator": "toy-evaluator-v1", "records": results,
          "behavior_trace": trace,
          "evaluation_sha256": hashlib.sha256(canonical).hexdigest()}
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
