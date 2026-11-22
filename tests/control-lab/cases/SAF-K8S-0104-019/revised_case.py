"""Check contextual ranking and provenance-bound applicability in Kubernetes Jobs."""
import json
from pathlib import Path
from runpy import run_path


HERE = Path(__file__).resolve().parent
BASE = run_path(str(HERE / "case.py"))
SCOPE = (
    "Kubernetes Jobs assess inert advisory metadata and synthetic inventory through ranking and "
    "build-specific evidence rules. The case retains unresolved cases with assigned review and "
    "a fixture deadline. Production inventory, advisories and response workflow remain open."
)


def run(lab):
    BASE["run"](lab)
    fixture_config = "saf-cve-build-evidence"
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": fixture_config},
        "data": {"fixtures.json": (HERE / "applicability.json").read_text(),
                 "triage.py": (HERE / "applicability.py").read_text()},
    })
    generic = {row["id"]: row for row in BASE["evaluate"](lab, "summary-only", fixture_config)}
    decisions = {row["id"]: row for row in BASE["evaluate"](lab, "build-evidence", fixture_config)}
    same = generic.keys() == decisions.keys()
    mislabeled = same and generic["managed-backport"]["status"] == "affected"
    lab.check("red", "The generic summary marks all four builds affected",
              mislabeled and all(row["status"] == "affected" for row in generic.values()),
              {"matched_inventory": same, "backport_marked_affected": mislabeled})

    backport = decisions["managed-backport"]
    exact = backport == {
        "id": "managed-backport", "build": "fixture-managed-003",
        "status": "not_affected", "disposition": "closed_with_evidence",
        "evidence": ["fixture-provider-a"],
    }
    lab.check("green", "The exact-build advisory supports a traceable closure decision",
              exact, {"matching_evidence_and_build": exact})

    def pending(row, expected_status):
        return (row["status"] == expected_status and row["disposition"] == "applicability_review"
                and row["owner"] == "synthetic-platform-triage"
                and row["deadline"] == "2026-11-22T12:00:00+00:00")

    conflict, missing = decisions["ambiguous-provider"], decisions["unknown-build"]
    open_items = {
        "conflict_retained": pending(conflict, "conflict")
        and conflict["evidence"] == ["fixture-provider-b", "fixture-provider-c"],
        "missing_build_retained": pending(missing, "incomplete")
        and missing["build"] is None and missing["evidence"] == [],
    }
    lab.check("green", "Conflicting or missing applicability evidence stays open for assigned review",
              all(open_items.values()), open_items)

    affected = decisions["inference-component"]
    assigned = (
        affected["status"] == "affected" and affected["disposition"] == "triage_required"
        and affected["owner"] == "synthetic-platform-triage"
        and affected["deadline"] == "2026-11-22T12:00:00+00:00"
        and affected["workload_impact"] == "inference"
        and affected["evidence"] == ["fixture-maintainer-d"]
    )
    lab.check("positive", "An affected record retains its owner, deadline and inference impact",
              assigned, {"owner_deadline_impact_retained": assigned})
