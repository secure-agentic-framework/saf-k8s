"""Metadata-only review of synthetic framework mapping records."""
import json
import sys

KNOWN = {
    "EU-AI-ACT-Article-12": "conditional-legal-obligation",
    "EU-AI-ACT-Article-15": "conditional-legal-obligation",
    "EU-AI-ACT-Annex-IV-5": "conditional-legal-obligation",
    "EU-AI-ACT-Annex-VI-3": "conditional-legal-obligation",
    "EU-AI-ACT-Article-55.1.b": "conditional-legal-obligation",
    "EU-AI-ACT-Article-9.1": "conditional-legal-obligation",
    "NIST-AI-RMF-GOVERN-1.1": "voluntary-framework-outcome",
    "AICPA-TSC-2017-CC6.1": "attestation-criterion",
    "AICPA-TSC-2017-CC7.2": "attestation-criterion",
}
SCENARIO_KEY = {
    "conditional-legal-obligation": "eu_ai_act",
    "voluntary-framework-outcome": "nist_ai_rmf",
    "attestation-criterion": "aicpa_trust_services_criteria",
}
REQUIRED = ("framework", "authority_type", "applicability_input", "coverage",
            "evidence_refs", "gap", "compensating_safeguards", "status")


def review(data, mode):
    source = data[mode]
    rows = source["rows"]
    findings = []
    observed_ids = set()
    for row in rows:
        rid = row.get("requirement_id", "")
        if rid in observed_ids:
            findings.append({"type": "duplicate-mapping-row", "requirement_id": rid})
        observed_ids.add(rid)
        expected = KNOWN.get(rid)
        if expected is None:
            findings.append({"type": "unknown-framework-identifier", "requirement_id": rid})
        elif row.get("authority_type") != expected:
            findings.append({"type": "misattributed-authority", "requirement_id": rid,
                             "declared": row.get("authority_type"), "expected": expected})
        if not row.get("evidence_refs"):
            findings.append({"type": "missing-evidence", "requirement_id": rid})
        expected_input = (data["scenario"][SCENARIO_KEY[expected]]["applicability_input"]
                          if expected in SCENARIO_KEY else None)
        if expected_input is None or row.get("applicability_input") != expected_input:
            findings.append({"type": "unapproved-applicability-input", "requirement_id": rid,
                             "value": row.get("applicability_input")})
        if mode in {"reviewed", "overclaimed"}:
            missing = [field for field in REQUIRED if field not in row]
            if missing:
                findings.append({"type": "missing-metadata", "requirement_id": rid, "fields": missing})
            evidence_refs = row.get("evidence_refs", [])
            absent = [ref for ref in evidence_refs if ref not in data.get("synthetic_evidence", {})]
            if absent:
                findings.append({"type": "unresolved-evidence-reference", "requirement_id": rid,
                                 "references": absent})
            if row.get("status") != "open" or row.get("coverage") not in (
                    "gap", "partial", "not-assessed", "mapping-link-present"):
                findings.append({"type": "unsupported-coverage-closure", "requirement_id": rid})
            if row.get("coverage") in ("gap", "partial", "not-assessed", "mapping-link-present"):
                if not row.get("gap") or not row.get("compensating_safeguards"):
                    findings.append({"type": "undocumented-open-gap", "requirement_id": rid})
                else:
                    findings.append({"type": "open-gap-recorded", "requirement_id": rid,
                                     "evidence_refs": evidence_refs,
                                     "compensating_safeguards": row["compensating_safeguards"]})
    if mode in {"reviewed", "overclaimed"}:
        missing_ids = sorted(set(KNOWN) - observed_ids)
        for rid in missing_ids:
            findings.append({"type": "missing-mapping-row", "requirement_id": rid})
        fatal = {"unknown-framework-identifier", "misattributed-authority", "missing-metadata",
                 "unresolved-evidence-reference", "undocumented-open-gap", "unapproved-applicability-input",
                 "missing-mapping-row", "duplicate-mapping-row", "unsupported-coverage-closure"}
    else:
        fatal = {"unknown-framework-identifier", "misattributed-authority"}
    return {
        "mode": mode,
        "mapping_id": source.get("mapping_id"),
        "control_id": source.get("control_id"),
        "review_type": "metadata-only",
        "legal_applicability_determined": False,
        "compliance_conclusion_made": False,
        "review_integrity_pass": not any(item["type"] in fatal for item in findings),
        "framework_coverage_complete": False,
        "findings": findings,
    }


def main():
    with open(sys.argv[1], encoding="utf-8") as stream:
        data = json.load(stream)
    print(json.dumps(review(data, sys.argv[2]), sort_keys=True))


if __name__ == "__main__":
    main()
