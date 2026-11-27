"""Check OCTAVE Phase 3 reference integrity without judging risk values."""
import argparse
import json
from datetime import date
from pathlib import Path

from review_gate import validate as validate_worksheet


def validate_trace(doc):
    errors = []
    criteria = {}
    for item in doc.get("risk_evaluation_criteria", []):
        criterion_id = item.get("id")
        outcomes = item.get("outcomes")
        if not criterion_id or criterion_id in criteria or not isinstance(outcomes, list) or not outcomes:
            errors.append("phase3-risk-criteria-invalid")
            continue
        criteria[criterion_id] = set(value for value in outcomes if isinstance(value, str) and value)

    for asset in doc.get("assets", []):
        aid = asset.get("id", "<missing>")
        evaluated = {}
        for threat in asset.get("threats", []):
            scenario = threat.get("scenario")
            evaluation = threat.get("evaluation") or {}
            criterion_ref = evaluation.get("criterion_ref")
            outcome = evaluation.get("outcome")
            if not isinstance(scenario, str) or not scenario:
                continue
            if scenario in evaluated:
                errors.append(f"phase3-risk-scenario-ambiguous:{aid}")
                continue
            if not isinstance(criterion_ref, str) or criterion_ref not in criteria:
                errors.append(f"phase3-risk-criterion-unresolved:{aid}")
            elif not isinstance(outcome, str) or not outcome or outcome not in criteria[criterion_ref]:
                errors.append(f"phase3-risk-outcome-invalid:{aid}")
            else:
                evaluated[scenario] = (criterion_ref, outcome)
        treatment = asset.get("risk_treatment") or {}
        treatment_ref = treatment.get("threat_ref")
        if not isinstance(treatment_ref, str) or not treatment_ref or treatment_ref not in evaluated:
            errors.append(f"phase3-treatment-threat-link-invalid:{aid}")
        priority = treatment.get("prioritization") or {}
        expected_evaluation = evaluated.get(treatment_ref)
        if (not expected_evaluation or priority.get("threat_ref") != treatment_ref
                or priority.get("criterion_ref") != expected_evaluation[0]
                or priority.get("outcome") != expected_evaluation[1]
                or not priority.get("priority") or not priority.get("rationale")):
            errors.append(f"phase3-priority-trace-invalid:{aid}")
    return sorted(set(errors))


def evaluate(path, evidence_root, as_of):
    doc = json.loads(Path(path).read_text())
    baseline = validate_worksheet(doc, Path(evidence_root), date.fromisoformat(as_of))
    errors = sorted(set(baseline["errors"] + validate_trace(doc)))
    return {"status": "fail" if errors else "pass", "errors": errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("worksheet", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--as-of", default="2026-11-22")
    args = parser.parse_args()
    result = evaluate(args.worksheet, args.evidence_root, args.as_of)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
