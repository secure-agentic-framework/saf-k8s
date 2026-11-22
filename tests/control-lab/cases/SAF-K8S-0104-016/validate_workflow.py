"""Static integrity checks for the synthetic SAF-K8S-0104-016 workflow record."""

import json
from datetime import datetime
from pathlib import Path


HERE = Path(__file__).resolve().parent


def parse_time(value):
    return datetime.fromisoformat(value)


def load(relative_path):
    return json.loads((HERE / relative_path).read_text(encoding="utf-8"))


def validate(workflow):
    finding = workflow["finding"]
    scope = finding["scope"]
    remediation = workflow["remediation"]
    retest = workflow["retest"]
    closure = workflow["closure"]
    baseline = load(finding["baseline_evidence"])
    changed = load(remediation["change_evidence"])
    retest_record = load(retest["evidence"])

    assert workflow["schema"] == "saf-k8s-remediation-workflow/v1"
    assert workflow["record_version"] == 2 and workflow["synthetic"] is True
    assert all(item["synthetic"] is True for item in (baseline, changed, retest_record))
    assert baseline["observed_value"] != remediation["target_value"]
    assert changed["observed_value"] == remediation["target_value"] == 0
    assert baseline["setting"] == changed["setting"] == scope["setting"]
    assert all(
        item[key] == scope[key]
        for item in (baseline, changed, retest_record)
        for key in ("cluster", "node", "kubernetes_version", "kind_version")
    )
    assert scope["kubernetes_version"] == "v1.36.1"
    assert scope["kind_version"] == "v0.32.0"
    assert "@sha256:" in scope["node_image"]

    detected = parse_time(finding["detected_at"])
    assigned = parse_time(remediation["assigned_at"])
    due = parse_time(remediation["due_at"])
    completed = parse_time(remediation["completed_at"])
    retested = parse_time(retest["performed_at"])
    closed = parse_time(closure["closed_at"])
    assert detected <= assigned <= completed <= retested <= closed <= due

    assert remediation["owner"]["synthetic"] is True
    assert retest["reviewer"]["synthetic"] is True
    assert retest["independent_of_owner"] is True
    assert retest["reviewer"]["name"] != remediation["owner"]["name"], "owner cannot approve own retest"
    assert retest["tested_revision"] == remediation["revision"] == 2
    assert retest_record["tested_revision"] == remediation["revision"]
    assert retest_record["reviewer"] == retest["reviewer"]["name"]
    assert retest_record["owner"] == remediation["owner"]["name"]
    assert retest_record["independent_of_owner"] is True
    assert retest_record["observed_value"] == remediation["target_value"]
    assert retest_record["result"] == retest["result"] == "pass"
    assert closure["status"] == "closed"
    assert closure["retest_evidence"] == retest["evidence"]
    assert closed >= retested

    events = workflow["events"]
    assert [event["sequence"] for event in events] == list(range(1, 6))
    assert [event["event"] for event in events] == [
        "detected", "assigned", "remediated", "retested", "closed"
    ]
    assert [parse_time(event["at"]) for event in events] == sorted(
        parse_time(event["at"]) for event in events
    )
    assert events[0]["revision"] == 1 and events[-1]["revision"] == 2

    live_template = load("evidence/live-recheck.template.json")
    assert live_template["status"] == "pending"
    assert live_template["result"] == "unverified"
    assert live_template["observed_readOnlyPort"] is None

if __name__ == "__main__":
    validate(load("remediation-workflow.json"))
    print("PASS: synthetic remediation, independent retest, and closure are internally linked")
