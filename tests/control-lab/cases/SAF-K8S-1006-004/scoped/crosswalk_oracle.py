"""Synthetic source-pinned crosswalk import and readiness projection."""
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-1006-004"
CATALOG_REVISION = "4e518d3bd0aab7847f62755ce1c7076d7478b3fb"
CONTROL_SHA256 = "8877e0aea2bbffdc28a808535c9c9920647990571e0060d3e184ab6fc9fdf3a2"
SOURCE_ID = "urn:example:saf:crosswalk-source:synthetic-v1"
SOURCE_VERSION = "1"
SOURCE_REVISION = "synthetic-revision-1"
SOURCE_SHA256 = "c9aedbe53f6a52c5db5ee509677c5043ed7d4d6770a1a0d94eec6f829a46ca04"
REQUIRED_OBJECTIVE = "SYN-OBJ-001"


def _read(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def _report(source, source_raw, crosswalk):
    gaps = []
    exact_source = (
        source.get("fixture_only") is True
        and source.get("source_id") == SOURCE_ID
        and source.get("source_version") == SOURCE_VERSION
        and source.get("source_revision") == SOURCE_REVISION
        and hashlib.sha256(source_raw).hexdigest() == SOURCE_SHA256
    )
    if not exact_source:
        gaps.append({"code": "source_pin_mismatch", "control_id": CONTROL_ID,
                     "expected_revision": SOURCE_REVISION})
    exact_catalog = (
        crosswalk.get("fixture_only") is True
        and crosswalk.get("catalog_revision") == CATALOG_REVISION
        and crosswalk.get("control_id") == CONTROL_ID
        and crosswalk.get("control_sha256") == CONTROL_SHA256
    )
    if not exact_catalog:
        gaps.append({"code": "control_catalog_pin_mismatch", "control_id": CONTROL_ID,
                     "expected_catalog_revision": CATALOG_REVISION,
                     "expected_control_sha256": CONTROL_SHA256})
    exact_source_link = (
        crosswalk.get("source_id") == SOURCE_ID
        and crosswalk.get("source_version") == SOURCE_VERSION
        and crosswalk.get("source_revision") == SOURCE_REVISION
        and crosswalk.get("source_sha256") == SOURCE_SHA256
    )
    if not exact_source_link:
        gaps.append({"code": "crosswalk_source_reference_stale", "control_id": CONTROL_ID,
                     "observed_source_revision": crosswalk.get("source_revision")})

    objectives = [row.get("id") for row in source.get("objectives", []) if isinstance(row, dict)]
    expected_rows = [row for row in crosswalk.get("links", [])
                     if isinstance(row, dict) and row.get("control_id") == CONTROL_ID]
    accepted = []
    for row in expected_rows:
        if row.get("control_sha256") != CONTROL_SHA256:
            gaps.append({"code": "control_reference_stale", "control_id": CONTROL_ID})
        if row.get("requirement_id") not in objectives:
            gaps.append({"code": "objective_not_in_pinned_source", "control_id": CONTROL_ID,
                         "requirement_id": row.get("requirement_id"),
                         "source_revision": crosswalk.get("source_revision")})
            continue
        if row.get("requirement_id") != REQUIRED_OBJECTIVE:
            gaps.append({"code": "unexpected_objective_reference", "control_id": CONTROL_ID,
                         "requirement_id": row.get("requirement_id")})
            continue
        if (row.get("relation_type") != "supports"
                or row.get("applicability") != "conditional"
                or not row.get("applicability_condition")):
            gaps.append({"code": "mapping_scope_fields_incomplete", "control_id": CONTROL_ID})
            continue
        if exact_source and exact_catalog and exact_source_link and row.get("control_sha256") == CONTROL_SHA256:
            accepted.append(row)

    if not expected_rows:
        gaps.append({"code": "missing_required_link", "control_id": CONTROL_ID,
                     "objective_id": REQUIRED_OBJECTIVE})
    if len(accepted) > 1:
        gaps.append({"code": "duplicate_mapping", "control_id": CONTROL_ID,
                     "accepted_link_count": len(accepted)})
    if not exact_source or not exact_catalog or not exact_source_link:
        accepted = []
    if len(accepted) != 1 and not gaps:
        gaps.append({"code": "required_link_not_uniquely_valid", "control_id": CONTROL_ID})

    # One diagnostic per code makes the dashboard projection stable and reviewable.
    unique_gaps = []
    seen = set()
    for gap in gaps:
        key = gap["code"]
        if key not in seen:
            unique_gaps.append(gap)
            seen.add(key)
    ready = not unique_gaps and len(accepted) == 1
    return {
        "fixture_only": True,
        "catalog_revision": crosswalk.get("catalog_revision"),
        "crosswalk_revision": crosswalk.get("crosswalk_revision"),
        "source_revision": crosswalk.get("source_revision"),
        "expected_control_count": 1,
        "verified_link_count": len(accepted),
        "gap_count": len(unique_gaps),
        "gaps": unique_gaps,
        "dashboard_status": "ready" if ready else "attention",
    }


def run(lab):
    source_raw = (HERE / "crosswalk-source.json").read_bytes()
    source = json.loads(source_raw)
    valid = _report(source, source_raw, _read("crosswalk-valid.json"))
    missing = _report(source, source_raw, _read("crosswalk-missing.json"))
    stale = _report(source, source_raw, _read("crosswalk-stale-objective.json"))
    lab.check("positive", "The source-pinned synthetic relation imports as a ready dashboard row",
              valid["dashboard_status"] == "ready" and valid["verified_link_count"] == 1
              and valid["gap_count"] == 0 and valid["gaps"] == [], valid)
    lab.check("red", "A required relation missing from the synthetic import appears as a dashboard gap",
              missing["dashboard_status"] == "attention" and missing["verified_link_count"] == 0
              and missing["gap_count"] == 1
              and missing["gaps"][0]["code"] == "missing_required_link", missing)
    stale_codes = {row["code"] for row in stale["gaps"]}
    lab.check("red", "A stale source revision and removed synthetic objective remain visible as dashboard gaps",
              stale["dashboard_status"] == "attention" and stale["verified_link_count"] == 0
              and {"crosswalk_source_reference_stale", "objective_not_in_pinned_source"}.issubset(stale_codes),
              stale)
    (lab.evidence / "crosswalk-readiness.raw.json").write_text(
        json.dumps({"fixture_only": True, "valid": valid, "missing": missing, "stale": stale},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
