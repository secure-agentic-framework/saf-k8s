"""Exercise attributable source selection and response clocks on inert records."""
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys


SCOPE = ("distribution", "component", "build")


def instant(value):
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def evaluate(fixture, at):
    now = instant(at)
    max_age = timedelta(hours=fixture["source_fresh_hours"])
    results = {}
    for item in fixture["inventory"]:
        provenance = [
            evidence for evidence in fixture["evidence"]
            if all(item[field] == evidence[field] for field in SCOPE)
            and evidence["issuer"] == fixture["authorities"][item["distribution"]]
            and 0 <= (now - instant(evidence["retrieved_at"])).total_seconds() <= max_age.total_seconds()
        ]
        states = {row["result"] for row in provenance}
        decision = next(iter(states)) if len(states) == 1 else "conflict" if states else "unknown"
        exposure = item.get("exposure")
        if not exposure or not 0 <= (now - instant(exposure["observed_at"])).total_seconds() <= max_age.total_seconds():
            exposure = {"value": "unknown", "evidence": None}
        row = {
            "decision": decision, "evidence": sorted(entry["id"] for entry in provenance),
            "exposure": exposure["value"], "exposure_evidence": exposure["evidence"],
        }
        if decision == "not_affected":
            row["disposition"] = "closed_with_evidence"
        else:
            policy = fixture["response_policy"]
            window = policy["impact_hours"][item["impact"]]
            due = instant(item["detected_at"]) + timedelta(hours=window)
            ack = instant(item["acknowledged_at"]) if item.get("acknowledged_at") else None
            overdue = ack > due if ack else now > due
            row.update(owner=item["owner"], due=due.isoformat(), overdue=overdue,
                       plan="respond" if decision == "affected" else "review",
                       disposition="escalate" if overdue else "open")
        results[item["id"]] = row
    return results


if __name__ == "__main__":
    fixture = json.loads(Path("/fixture/fixtures.json").read_text())
    print(json.dumps(evaluate(fixture, fixture["checkpoints"][sys.argv[1]]), sort_keys=True))
