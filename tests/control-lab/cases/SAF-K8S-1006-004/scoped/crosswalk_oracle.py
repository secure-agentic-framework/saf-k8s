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


# Frozen canonical crosswalk counterfactual. The repo source files are not read at runtime;
# their revision and fingerprints were checked when this allowlisted fixture was staged.
CANONICAL_FIXTURE_SHA256 = "3a8904bbe813bf7005700d3bfd07b95e51da275602a68149472024078d169c83"
CANONICAL_ROWS_SHA256 = "53d7ed041a831c2ec6e0dec15cb55396a2fa8adc4dc1b5fa7d77b9dfd0e776be"
CANONICAL_REVERSE_LINKS_SHA256 = "92930c8fb9b05a560de03ea1f4bde4547db05be7f2480d2a9e8fe383e6e1cbe8"
CANONICAL_EXPECTED_ROWS = 16
CANONICAL_REPOSITORY_REVISION = "2673765fb440949d181085671aacec31fb29ca79"
CANONICAL_CROSSWALK_SHA256 = "a69e0430703c928fd5179c6c5d1e0be62137d02ee715b742fa70dd76cce51441"
CANONICAL_CONTROL_ROW_SHA256 = "8877e0aea2bbffdc28a808535c9c9920647990571e0060d3e184ab6fc9fdf3a2"
CANONICAL_CONTROL_MARKDOWN_SHA256 = "29d24690010bf23296a72b715da2d7cfb9c3284468e7232979dde467b4642d77"


def _row_key(row):
    return (row.get("framework_code"), row.get("framework_version"), row.get("framework_requirement_id", row.get("requirement_id")))


def _canonical_projection(candidate, reference):
    expected_rows = {_row_key(row): row for row in reference["rows"]}
    expected_links = {_row_key(row): row for row in reference["reverse_links"]}
    source = candidate.get("source", {})
    gaps = []
    source_pins_valid = (
        source.get("repository_revision") == CANONICAL_REPOSITORY_REVISION
        and source.get("crosswalk_sha256") == CANONICAL_CROSSWALK_SHA256
        and source.get("control_row_sha256") == CANONICAL_CONTROL_ROW_SHA256
        and source.get("control_markdown_sha256") == CANONICAL_CONTROL_MARKDOWN_SHA256
        and source.get("control_id") == CONTROL_ID
        and source.get("catalog_revision") == CATALOG_REVISION
    )
    if not source_pins_valid:
        gaps.append("crosswalk_source_reference_stale")

    candidate_rows = candidate.get("rows", [])
    candidate_links = candidate.get("reverse_links", [])
    rows_by_key = {}
    links_by_key = {}
    for row in candidate_rows:
        key = _row_key(row)
        rows_by_key.setdefault(key, []).append(row)
    for link in candidate_links:
        key = _row_key(link)
        links_by_key.setdefault(key, []).append(link)

    verified = 0
    for key, expected in expected_rows.items():
        row_matches = rows_by_key.get(key, [])
        link_matches = links_by_key.get(key, [])
        if not row_matches:
            gaps.append("missing_required_link")
            continue
        if len(row_matches) != 1:
            gaps.append("duplicate_mapping")
            continue
        if row_matches[0] != expected:
            gaps.append("altered_or_unexpected_row")
            continue
        expected_link = expected_links.get(key)
        if len(link_matches) != 1 or not expected_link or link_matches[0] != expected_link:
            gaps.append("reverse_link_mismatch")
            continue
        if source_pins_valid:
            verified += 1

    unexpected_rows = [key for key in rows_by_key if key not in expected_rows]
    unexpected_links = [key for key in links_by_key if key not in expected_links]
    if unexpected_rows or unexpected_links:
        gaps.append("unexpected_mapping_or_reverse_link")

    unresolved = sum(row.get("applicability") == "conditional" for row in candidate_rows)
    # Preserve each unresolved applicable-row gap even if stale source metadata quarantines it.
    unresolved_gap_count = unresolved
    if unresolved:
        gaps.append("applicability_unresolved")
    if gaps or unresolved:
        status = "attention"
    else:
        status = "ready"
    return {
        "fixture_only": True,
        "expected_control_count": 1,
        "verified_link_count": verified,
        "applicability_unresolved_count": unresolved,
        "unresolved_gap_count": unresolved_gap_count,
        "gap_codes": sorted(set(gaps)),
        "dashboard_status": status,
        "source_pins_valid": source_pins_valid,
        "candidate_row_count": len(candidate_rows),
        "candidate_reverse_link_count": len(candidate_links),
    }


def run_canonical(lab):
    raw = (HERE / "canonical-crosswalk-fixture.json").read_bytes()
    fixture = json.loads(raw)
    rows_bytes = json.dumps(fixture["rows"], sort_keys=True, separators=(",", ":")).encode()
    links_bytes = json.dumps(fixture["reverse_links"], sort_keys=True, separators=(",", ":")).encode()
    fixture_pins_valid = (
        hashlib.sha256(raw).hexdigest() == CANONICAL_FIXTURE_SHA256
        and hashlib.sha256(rows_bytes).hexdigest() == CANONICAL_ROWS_SHA256
        and hashlib.sha256(links_bytes).hexdigest() == CANONICAL_REVERSE_LINKS_SHA256
        and len(fixture["rows"]) == CANONICAL_EXPECTED_ROWS
        and len(fixture["reverse_links"]) == CANONICAL_EXPECTED_ROWS
        and all(row.get("control_id") == CONTROL_ID and row.get("relation_type") == "supports" for row in fixture["rows"])
        and all(row.get("applicability") == "conditional" for row in fixture["rows"])
    )
    canonical = _canonical_projection(fixture, fixture)
    lab.check("positive", "Canonical structured rows and each exact generated reverse-page path/hash match the pinned repository fixture",
              fixture_pins_valid and canonical["verified_link_count"] == CANONICAL_EXPECTED_ROWS
              and canonical["applicability_unresolved_count"] == CANONICAL_EXPECTED_ROWS
              and canonical["dashboard_status"] == "attention", canonical)

    missing_fixture = json.loads(raw)
    removed_key = _row_key(missing_fixture["rows"].pop(0))
    missing_fixture["reverse_links"] = [link for link in missing_fixture["reverse_links"] if _row_key(link) != removed_key]
    missing = _canonical_projection(missing_fixture, fixture)
    lab.check("red", "A removed canonical relation remains an explicit missing-link counterfactual",
              "missing_required_link" in missing["gap_codes"]
              and missing["verified_link_count"] == CANONICAL_EXPECTED_ROWS - 1
              and missing["dashboard_status"] == "attention", missing)

    stale_fixture = json.loads(raw)
    stale_fixture["source"]["crosswalk_sha256"] = "0" * 64
    stale = _canonical_projection(stale_fixture, fixture)
    lab.check("red", "Stale canonical metadata quarantines relation rows while preserving unresolved applicability gaps",
              "crosswalk_source_reference_stale" in stale["gap_codes"]
              and stale["verified_link_count"] == 0
              and stale["applicability_unresolved_count"] == CANONICAL_EXPECTED_ROWS
              and stale["dashboard_status"] == "attention", stale)

    reverse_fixture = json.loads(raw)
    reverse_fixture["reverse_links"][0]["reverse_page_sha256"] = "0" * 64
    reverse = _canonical_projection(reverse_fixture, fixture)
    lab.check("red", "An altered reverse-page fingerprint is rejected for its exact relation",
              "reverse_link_mismatch" in reverse["gap_codes"]
              and reverse["verified_link_count"] == CANONICAL_EXPECTED_ROWS - 1
              and reverse["applicability_unresolved_count"] == CANONICAL_EXPECTED_ROWS
              and reverse["dashboard_status"] == "attention", reverse)

    (lab.evidence / "canonical-crosswalk-counterfactual.raw.json").write_text(
        json.dumps({"fixture_only": True, "fixture_sha256": CANONICAL_FIXTURE_SHA256,
                    "rows_sha256": CANONICAL_ROWS_SHA256, "reverse_links_sha256": CANONICAL_REVERSE_LINKS_SHA256,
                    "canonical": canonical, "missing": missing, "stale": stale, "reverse_link": reverse},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
