"""Evaluate the case's fictional findings against a fixed versioned policy."""
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys


def clock(value):
    return datetime.fromisoformat(value)


def classify(finding):
    if finding["security_signal"] == "priority-review":
        return "priority"
    if finding["context"] == "unknown":
        return "triage"
    return finding["context"]


def decision(policy, finding, context, now):
    tier = classify({**finding, "context": context})
    due = clock(finding["opened"]) + timedelta(hours=policy["targets"][tier]["hours"])
    action = "open-within-target" if now < due else "overdue"
    completion = finding.get("verification")
    if completion and completion["artifact"] == finding["artifact"] and completion["reviewed"]:
        closed = clock(completion["at"])
        if clock(finding["opened"]) <= closed <= now:
            action = "remediated-on-time" if closed <= due else "remediated-late"
    exception = finding.get("exception")
    if action == "overdue" and exception:
        granted = exception["approver"] in policy["exception_approvers"]
        scoped = exception["finding"] == finding["id"] and exception["artifact"] == finding["artifact"]
        active = clock(exception["start"]) <= now < clock(exception["expires"])
        if granted and scoped and active:
            action = "approved-deferral"
    return {"priority": policy["targets"][tier]["priority"], "tier": tier,
            "owner": policy["targets"][tier]["owner"], "due": due.isoformat(), "disposition": action}


def evaluate(policy, inputs, as_of):
    now = clock(as_of)
    decisions = {}
    for finding in inputs["findings"]:
        entry = inputs["workloads"].get(finding["workload"], {})
        proven = entry.get("artifact") == finding["artifact"] and entry.get("owner_observed")
        context = entry["context"] if proven else "unknown"
        decisions[finding["id"]] = decision(policy, finding, context, now)
    ordered = sorted(decisions, key=lambda name: (decisions[name]["priority"], decisions[name]["due"], name))
    return {"policy_revision": policy["revision"], "evaluated_at": as_of, "ordered": ordered,
            "decisions": decisions, "blockers": [name for name in ordered if decisions[name]["disposition"] == "overdue"]}


def main():
    root = Path("/fixture")
    result = evaluate(json.loads((root / "policy.json").read_text()),
                      json.loads((root / "findings.json").read_text()), sys.argv[1])
    print(json.dumps(result, sort_keys=True))
    return 23 if result["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
