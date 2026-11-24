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

    config = "saf-cve-timed-review"
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config}, "immutable": True,
        "data": {"fixtures.json": (HERE / "timed-review.json").read_text(),
                 "triage.py": (HERE / "timed-review.py").read_text()},
    })
    before = BASE["evaluate"](lab, "before-due", config)
    after = BASE["evaluate"](lab, "after-due", config)
    covered = after["covered"]
    unknown = {
        key: after[key]["decision"] == after[key]["exposure"] == "unknown"
        and after[key]["disposition"] == "open" and bool(after[key]["owner"])
        and after[key]["evidence"] == []
        for key in ("wrong-issuer", "stale-evidence")
    }
    lab.check("green", "Matching build text and an older exposure observation cannot authorize closure",
              all(unknown.values()) and covered["disposition"] == "closed_with_evidence"
              and covered["evidence"] == ["exact-authority"],
              {**unknown, "fresh_authoritative_example": covered["decision"]})
    timely, late = before["critical-affected"], after["critical-affected"]
    invariant = timely["due"] == late["due"] == "2026-11-21T04:00:00+00:00"
    lab.check("green", "Later re-evaluation escalates the same deadline instead of restarting it",
              invariant and not timely["overdue"] and late["overdue"]
              and late["disposition"] == "escalate" and late["owner"] == timely["owner"]
              and late["exposure"] == "reachable" and late["exposure_evidence"] == "fixture-current-topology",
              {"stable_due": invariant, "before_overdue": timely["overdue"], "after_overdue": late["overdue"],
               "dated_exposure_evidence": late["exposure_evidence"]})
    (lab.evidence / "triage-timing.raw.json").write_text(
        json.dumps({"before_deadline": before, "after_deadline": after}, indent=2) + "\n")
