"""Completeness gate for a three-phase OCTAVE worksheet; no risk scoring."""
import argparse
import json
from datetime import date
from pathlib import Path

PHASES = {"phase1": "Build Asset-Based Threat Profiles",
          "phase2": "Identify Infrastructure Vulnerabilities",
          "phase3": "Develop Security Strategy and Plans"}


ASSET_CLASSES = {"model", "training-data", "gpu-infrastructure", "inference-endpoint"}
PHASE_REFS = {"phase1": "workshop_record", "phase2": "scope_record", "phase3": "plan_record"}


def valid_evidence(root, ref):
    if not isinstance(ref, str) or not ref:
        return False
    target = (root / ref).resolve()
    return target.is_relative_to(root) and target.is_file()


def notes_for_asset(asset, root):
    errors = []
    aid = asset.get("id", "<missing>")
    for key in ("class", "criticality", "owner", "business_service", "security_requirements"):
        if not asset.get(key):
            errors.append(f"phase1-{key}-missing:{aid}")
    impacts = asset.get("impacts") or []
    if not impacts:
        errors.append(f"phase1-impact-missing:{aid}")
    threats = asset.get("threats") or []
    if not threats:
        errors.append(f"phase1-threat-profile-missing:{aid}")
    for threat in threats:
        if not threat.get("scenario") or threat.get("impact_ref") not in impacts:
            errors.append(f"phase1-threat-impact-link-invalid:{aid}")
    components = asset.get("infrastructure") or []
    if not components:
        errors.append(f"phase2-infrastructure-link-missing:{aid}")
    for component in components:
        if not component.get("component") or not valid_evidence(root, component.get("vulnerability_review_ref")):
            errors.append(f"phase2-vulnerability-evidence-missing:{aid}")
    tolerance = asset.get("organizational_tolerance") or {}
    if not tolerance.get("threshold") or not valid_evidence(root, tolerance.get("source_ref")):
        errors.append(f"phase3-tolerance-missing:{aid}")
    decision = asset.get("risk_treatment") or {}
    if not all(decision.get(key) for key in ("choice", "business_justification", "owner")):
        errors.append(f"phase3-treatment-missing:{aid}")
    if (not impacts or set(decision.get("impact_refs") or []) != set(impacts)
            or not tolerance.get("source_ref") or decision.get("tolerance_ref") != tolerance.get("source_ref")):
        errors.append(f"phase3-treatment-trace-invalid:{aid}")
    if not valid_evidence(root, decision.get("residual_risk_ref")):
        errors.append(f"phase3-residual-review-missing:{aid}")
    return errors


def validate(doc, root, as_of):
    root = root.resolve()
    errors = []
    for phase, title in PHASES.items():
        record = doc.get("phases", {}).get(phase, {})
        if record.get("method") != title:
            errors.append(f"{phase}-method-mismatch")
        if not valid_evidence(root, record.get(PHASE_REFS[phase])):
            errors.append(f"{phase}-evidence-missing")
    assets = doc.get("assets") or []
    classes = {asset.get("class") for asset in assets}
    if classes & {"proprietary-model", "open-model"}:
        classes.add("model")
    if not ASSET_CLASSES <= classes:
        errors.append("required-asset-classes-missing")
    identifiers = [asset.get("id") for asset in assets]
    if not all(identifiers) or len(identifiers) != len(set(identifiers)):
        errors.append("asset-identifiers-invalid")
    for asset in assets:
        errors.extend(notes_for_asset(asset, root))
    cadence = doc.get("review_cadence", {})
    try:
        due = date.fromisoformat(cadence.get("annual_due") or "")
    except ValueError:
        due = None
    if due is None or due < as_of or not all(cadence.get(key) for key in ("change_triggers", "owner")):
        errors.append("review-cadence-missing")
    for name, key in (("organization_scoring", "scheme_ref"), ("stakeholder_outcomes", "record_ref")):
        if not valid_evidence(root, (doc.get(name) or {}).get(key)):
            errors.append(f"{name}-evidence-missing")
    return {"status": "fail" if errors else "pass", "errors": sorted(set(errors))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("worksheet", type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    document = json.loads(args.worksheet.read_text())
    result = validate(document, args.worksheet.parent, args.as_of)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
