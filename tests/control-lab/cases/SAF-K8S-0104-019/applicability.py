"""Resolve exact-build evidence for the bounded synthetic triage example."""
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys


def resolve(fixture, build):
    entries = [row for row in fixture["applicability"] if row["build"] == build["installed"]]
    statuses = {row["status"] for row in entries}
    source = sorted(row["advisory"] for row in entries)
    if not statuses:
        status = "incomplete"
    elif len(statuses) > 1:
        status = "conflict"
    else:
        status = next(iter(statuses))

    record = {"id": build["id"], "build": build["installed"], "status": status, "evidence": source}
    if status == "not_affected":
        return {**record, "disposition": "closed_with_evidence"}
    workflow = fixture["policy"]
    start = datetime.fromisoformat(fixture["reviewed_at"].removesuffix("Z") + "+00:00")
    deadline = start + timedelta(hours=workflow["response_hours"])
    return {
        **record,
        "disposition": "triage_required" if status == "affected" else "applicability_review",
        "owner": workflow["owner"],
        "deadline": deadline.isoformat(),
        "workload_impact": build.get("workload_impact"),
    }


if __name__ == "__main__":
    fixture = json.loads(Path("/fixture/fixtures.json").read_text())
    mode = sys.argv[1]
    if mode == "summary-only":
        records = [{"id": row["id"], "status": fixture["summary"]} for row in fixture["builds"]]
    elif mode == "build-evidence":
        records = [resolve(fixture, row) for row in fixture["builds"]]
    else:
        raise ValueError("unknown evidence scope")
    print(json.dumps(records, sort_keys=True))
