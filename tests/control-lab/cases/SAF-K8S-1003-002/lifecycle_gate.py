"""Bounded assessment freshness checks for the scratch 1003-002 extension."""
import argparse
import calendar
import json
from datetime import date
from pathlib import Path

from review_gate import validate


def anniversary(reviewed_on):
    """One calendar year later; Feb 29 reviews fall due Feb 28 in common years."""
    year = reviewed_on.year + 1
    day = min(reviewed_on.day, calendar.monthrange(year, reviewed_on.month)[1])
    return date(year, reviewed_on.month, day)


def cadence_errors(cadence, as_of):
    errors = []
    try:
        reviewed_on = date.fromisoformat(cadence.get("last_review") or "")
    except ValueError:
        reviewed_on = None
    try:
        due = date.fromisoformat(cadence.get("annual_due") or "")
    except ValueError:
        due = None
    if reviewed_on is None or due is None:
        return ["review-cadence-date-invalid"]
    if reviewed_on > as_of:
        errors.append("review-date-in-future")
    expected_latest_due = anniversary(reviewed_on)
    if due > expected_latest_due:
        errors.append("annual-due-after-anniversary")
    if due < reviewed_on:
        errors.append("annual-due-before-review")
    if as_of > due:
        errors.append("review-overdue")
    return errors


def review_errors(doc, state, as_of):
    cadence = doc.get("review_cadence") or {}
    errors = cadence_errors(cadence, as_of)
    reviewed = cadence.get("reviewed_change") or {}
    for key in ("uid", "revision", "topology_sha256"):
        if not reviewed.get(key) or reviewed.get(key) != state.get(key):
            errors.append("major-change-review-stale")
            break
    return sorted(set(errors))


def run_document(worksheet_path, state_path, as_of):
    worksheet_path = Path(worksheet_path)
    doc = json.loads(worksheet_path.read_text())
    state = json.loads(Path(state_path).read_text())
    base = validate(doc, worksheet_path.parent, as_of)
    errors = sorted(set(base["errors"] + review_errors(doc, state, as_of)))
    return {"status": "fail" if errors else "pass", "errors": errors}


def run_cadence_cases(path):
    cases = json.loads(Path(path).read_text())
    results = {}
    for case in cases:
        errors = cadence_errors(case["cadence"], date.fromisoformat(case["as_of"]))
        results[case["name"]] = {"status": "fail" if errors else "pass", "errors": errors}
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("worksheet", nargs="?")
    parser.add_argument("state", nargs="?")
    parser.add_argument("--as-of", type=date.fromisoformat)
    parser.add_argument("--cadence-cases")
    args = parser.parse_args()
    if args.cadence_cases:
        result = run_cadence_cases(args.cadence_cases)
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0)
    if not args.worksheet or not args.state or args.as_of is None:
        parser.error("worksheet, state, and --as-of are required")
    result = run_document(args.worksheet, args.state, args.as_of)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
