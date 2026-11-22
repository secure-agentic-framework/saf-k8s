"""Validate a scoped ATT&CK mapping and its synthetic evidence."""
from datetime import date
import json
from pathlib import Path
import sys


def load(root, name):
    return json.loads((root / name).read_text())


def evaluate(mapping, known, events, mitigations, as_of):
    errors = []
    provenance = mapping.get("source", {})
    if provenance.get("release") != known["release"]:
        errors.append("source-release-mismatch")
    review = mapping.get("review", {})
    try:
        due = date.fromisoformat(review.get("next_due", ""))
    except ValueError:
        due = None
    if not due or due < as_of or not review.get("owner") or not review.get("change_triggers"):
        errors.append("review-cadence-missing")

    rows = mapping.get("techniques", [])
    identifiers = [row.get("technique_id") for row in rows]
    if set(identifiers) != set(known["techniques"]) or len(identifiers) != len(set(identifiers)):
        errors.append("technique-inventory-mismatch")
    results = []
    for row in rows:
        technique = row["technique_id"]
        original = known["techniques"].get(technique)
        if not original or "Containers" not in original["platforms"]:
            errors.append(f"containers-platform-link-invalid:{technique}")
        elif (row.get("name") != original["name"] or row.get("url") != original["url"]
              or row.get("tactic") not in original["tactics"]):
            errors.append(f"official-technique-or-tactic-mismatch:{technique}")
        if row.get("coverage_status") not in {"none", "partial", "documented"}:
            errors.append(f"unsupported-coverage-state:{technique}")
        if row.get("deployed_protection") != "unknown":
            errors.append(f"deployment-claim-lacks-independent-evidence:{technique}")

        evidence = row.get("defensive_evidence", {})
        event = evidence.get("detection") or {}
        refs = event.get("event_ids") or []
        if (event.get("source") != "synthetic-policy-events.json" or not refs
                or not event.get("description") or any(
                    events.get(key, {}).get("mapped_technique") != technique for key in refs)):
            errors.append(f"event-reference-mismatch:{technique}")
        mitigation = evidence.get("mitigation") or {}
        detail = mitigations.get(mitigation.get("record_id"), {})
        if (mitigation.get("evidence_ref") != "mitigation-review.json"
                or detail.get("technique_id") != technique
                or detail.get("statement") != mitigation.get("control")):
            errors.append(f"mitigation-reference-mismatch:{technique}")
        gap = row.get("gap", {})
        if gap.get("status") != "open" or not all(gap.get(field) for field in ("owner", "due", "description", "disposition")):
            errors.append(f"gap-disposition-missing:{technique}")
        results.append({"technique": technique, "tactic": row.get("tactic", {}).get("id"),
                        "deployment": row.get("deployed_protection"), "coverage": row.get("coverage_status"),
                        "gap": gap.get("status"), "owner": gap.get("owner")})
    return {"status": "fail" if errors else "pass", "errors": sorted(errors),
            "results": results, "metadata_sha256": known["upstream_sha256"]}


def main():
    root = Path(sys.argv[1]).parent
    verdict = evaluate(
        load(root, Path(sys.argv[1]).name), load(root, "attack-metadata.json"),
        {row["event_id"]: row for row in load(root, "synthetic-policy-events.json")["events"]},
        {row["id"]: row for row in load(root, "mitigation-review.json")["records"]},
        date.fromisoformat(sys.argv[2]),
    )
    print(json.dumps(verdict, sort_keys=True))
    raise SystemExit(1 if verdict["errors"] else 0)


if __name__ == "__main__":
    main()
