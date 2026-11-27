"""Metadata-only review of synthetic framework mapping records."""
import json
import sys
from copy import deepcopy

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

# Versioned, source-backed identities for this synthetic review fixture. These
# identify editions and publication records; they are not applicability
# decisions and the reviewer does not fetch or interpret the sources.
SOURCE_IDENTITIES = {
    "EU-AI-ACT": {
        "framework": "EU AI Act",
        "edition": "Regulation (EU) 2024/1689",
        "source_uri": "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng",
        "revision": "Consolidated text current 2026-07-27",
    },
    "NIST-AI-RMF": {
        "framework": "NIST AI RMF",
        "edition": "1.0",
        "source_uri": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
        "revision": "NIST AI 100-1, 2023-01",
    },
    "AICPA-TSC": {
        "framework": "AICPA Trust Services Criteria",
        "edition": "2017, revised points of focus 2022",
        "source_uri": "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
        "revision": "2017 TSC with revised points of focus 2022",
    },
    "NIST-800-53": {
        "framework": "NIST SP 800-53 Revision 5",
        "edition": "Release 5.2.0",
        "source_uri": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "revision": "SP 800-53 Release 5.2.0, 2025-08-27",
    },
    "NIST-SSDF": {
        "framework": "NIST SP 800-218 SSDF",
        "edition": "Version 1.1",
        "source_uri": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "revision": "SP 800-218 Final, 2022-02-03",
    },
    "NIST-SSDF-AI": {
        "framework": "NIST SP 800-218A",
        "edition": "Final",
        "source_uri": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
        "revision": "SP 800-218A Final, 2024-07-26",
    },
}
MAPPING_SOURCE_IDS = {'eu-ai-act-crosswalk': 'EU-AI-ACT',
    'nist-ai-rmf-crosswalk': 'NIST-AI-RMF',
    'aicpa-tsc-crosswalk': 'AICPA-TSC',
    'nist-800-53-crosswalk': 'NIST-800-53',
    'nist-ssdf-crosswalk': 'NIST-SSDF',
    'nist-ssdf-ai-profile': 'NIST-SSDF-AI'}
SOURCE_FIELDS = ("framework", "edition", "source_uri", "reviewed_revision")


def classify_source_record(record, source_identity, current_revision=None):
    if not isinstance(record, dict) or not isinstance(source_identity, dict):
        return "unknown"
    if any(not record.get(field) for field in SOURCE_FIELDS):
        return "unknown"
    exact = all(record.get(field) == source_identity.get(field)
                for field in ("framework", "edition", "source_uri"))
    if not exact:
        return "conflict"
    current_revision = current_revision or source_identity.get("revision")
    if not current_revision:
        return "unknown"
    if record["reviewed_revision"] != current_revision:
        return "review-required"
    return "current"


def review_sources(data):
    source_review = data.get("source_review")
    if not isinstance(source_review, dict):
        return {"mode": "source-review", "review_type": "metadata-only",
                "review_integrity_pass": False, "matrix": {"missing_source_catalog": "unknown"},
                "legal_applicability_determined": False, "compliance_conclusion_made": False}

    records = source_review.get("records", [])
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        records = []
    matrix = {}
    for row in records:
        source_id = row.get("source_id")
        identity = SOURCE_IDENTITIES.get(source_id)
        key = row.get("mapping_key", "")
        bound = bool(key) and MAPPING_SOURCE_IDS.get(key) == source_id and identity is not None
        matrix[key] = classify_source_record(row, identity) if bound else "conflict"

    wrong_edition = deepcopy(records[0]) if records else {}
    if wrong_edition:
        wrong_edition["edition"] = "unapproved fixture edition"
    stale_source = deepcopy(records[0]) if records else {}
    missing_identity = deepcopy(records[0]) if records else {}
    if missing_identity:
        missing_identity.pop("source_uri", None)

    first_identity = SOURCE_IDENTITIES.get(records[0].get("source_id")) if records else None
    counterfactuals = {
        "wrong_edition": classify_source_record(wrong_edition, first_identity),
        "source_change_requires_review": classify_source_record(
            stale_source, first_identity, "synthetic-source-change-r2"),
        "missing_source_identity": classify_source_record(missing_identity, first_identity),
    }
    expected_keys = set(MAPPING_SOURCE_IDS)
    all_current = (set(matrix) == expected_keys and len(records) == len(expected_keys)
                   and all(value == "current" for value in matrix.values()))
    return {
        "mode": "source-review",
        "control_id": source_review.get("control_id"),
        "review_type": "metadata-only",
        "review_integrity_pass": all_current,
        "matrix": matrix,
        "counterfactuals": counterfactuals,
        "legal_applicability_determined": False,
        "compliance_conclusion_made": False,
        "framework_coverage_complete": False,
    }


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
    mode = sys.argv[2]
    result = review_sources(data) if mode == "source-review" else review(data, mode)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
