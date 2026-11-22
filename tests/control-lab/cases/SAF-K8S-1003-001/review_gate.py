"""Check completeness and workflow state for STRIDE review records."""
from datetime import date
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED_COMPONENTS = (
    "api-server", "etcd", "kubelet", "scheduler", "container-runtime",
    "kubeflow-operator", "kserve-controller", "gpu-device-plugin",
    "model-serving-endpoint",
)
REQUIRED_STRIDE = (
    "spoofing", "tampering", "repudiation", "information-disclosure",
    "denial-of-service", "elevation-of-privilege",
)
REQUIRED_THREAT_FIELDS = (
    "id", "component", "category", "risk", "mitigation", "evidence",
    "owner", "status",
)


def evaluate(record, evidence_root=ROOT, today=None):
    """Return deterministic structural/workflow findings; never judge risk merit."""
    today = today or date.today()
    errors = []
    components = record.get("components", {})
    for component in REQUIRED_COMPONENTS:
        entry = components.get(component)
        if not isinstance(entry, dict) or not entry.get("boundary") or not entry.get("data_flows"):
            errors.append(f"component-incomplete:{component}")
        elif isinstance(entry.get("data_flows"), list):
            for link in entry["data_flows"]:
                path = (evidence_root / link).resolve()
                if not path.is_relative_to(evidence_root.resolve()) or not path.is_file():
                    errors.append(f"data-flow-link-invalid:{component}:{link}")
    coverage = record.get("coverage", {})
    threats = record.get("threats", [])
    by_id = {threat.get("id"): threat for threat in threats}
    if len(by_id) != len(threats):
        errors.append("threat-ids-duplicated")
    referenced = set()
    for component in REQUIRED_COMPONENTS:
        for category in REQUIRED_STRIDE:
            cell = coverage.get(component, {}).get(category, {})
            key = f"{component}:{category}"
            status = cell.get("status") if isinstance(cell, dict) else ""
            if status == "threat":
                links = cell.get("threat_ids", [])
                complete = links and all(
                    link in by_id and by_id[link].get("component") == component
                    and by_id[link].get("category") == category for link in links)
                if complete:
                    referenced.update(links)
                else:
                    errors.append(f"threat-coverage-unlinked:{key}")
            elif status == "not-applicable":
                if not cell.get("rationale"):
                    errors.append(f"disposition-rationale-required:{key}")
            else:
                errors.append(f"coverage-missing:{key}")
    if set(by_id) - referenced:
        errors.append("unreferenced-threat-record")
    for index, threat in enumerate(threats):
        for field in REQUIRED_THREAT_FIELDS:
            if not threat.get(field):
                errors.append(f"threat-field-missing:{index}:{field}")
        for link in threat.get("evidence", []):
            path = (evidence_root / link).resolve()
            if not path.is_relative_to(evidence_root.resolve()) or not path.is_file():
                errors.append(f"evidence-link-invalid:{link}")
    freshness = record.get("review", {}).get("review_due")
    try:
        if not freshness or date.fromisoformat(freshness) < today:
            errors.append("review-stale-or-missing")
    except ValueError:
        errors.append("review-due-invalid")
    review = record.get("review", {})
    if not record.get("change_triggers"):
        errors.append("change-triggers-missing")
    if review.get("stage") != "security-architecture-approved":
        errors.append("stage-approval-missing")
    approvals = review.get("approvals", [])
    roles = {a.get("role") for a in approvals if a.get("reviewer") and a.get("decision") == "approved"}
    if not {"security-architecture", "platform-engineering"}.issubset(roles):
        errors.append("independent-approvals-missing")
    reviewers_by_role = {
        a.get("role"): a.get("reviewer") for a in approvals
        if a.get("role") in {"security-architecture", "platform-engineering"}
        and a.get("decision") == "approved" and a.get("reviewer")
    }
    if len(reviewers_by_role) == 2 and len(set(reviewers_by_role.values())) != 2:
        errors.append("approval-reviewers-not-distinct")
    return {"status": "pass" if not errors else "fail", "errors": errors}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--today", help="Override date for deterministic replay (YYYY-MM-DD)")
    args = parser.parse_args()
    result = evaluate(json.loads(args.record.read_text()), args.record.parent,
                      date.fromisoformat(args.today) if args.today else None)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
