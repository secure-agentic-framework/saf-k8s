#!/usr/bin/env python3
"""Offline lifecycle-policy demonstration over synthetic OCI-shaped records."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path


CASE_DIR = Path(__file__).resolve().parent
SCOPE = (
    "Verify exact OCI subject and referrer descriptors, synthetic lifecycle eligibility and "
    "orphan hold. Exercise a disposable loopback-only OCI registry with three synthetic "
    "metadata manifest types, then observe early-loss baseline, protected retention and "
    "eligible retirement. The extended fixture exercises both OCI discovery modes, synthetic DSSE validation, "
    "digest-preserving copies, and Distribution filesystem GC. Production retention and replication remain separate."
)
EMPTY_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
EMPTY_DESCRIPTOR = {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": EMPTY_DIGEST,
    "size": 2,
}
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def read_json(name: str) -> dict:
    return json.loads((CASE_DIR / name).read_text(encoding="utf-8"))


def build_store(fixtures: dict) -> tuple[dict, dict]:
    subjects = {}
    for entry in fixtures["subjects"]:
        manifest = entry["manifest"]
        digest = content_digest(manifest)
        subjects[entry["id"]] = {
            **entry,
            "digest": digest,
            "size": len(canonical_bytes(manifest)),
        }

    objects = {}
    for subject in subjects.values():
        objects[(subject["repository"], subject["digest"])] = {
            **subject,
            "kind": "subject",
        }

    referrers = {}
    for entry in fixtures["referrers"]:
        target = subjects.get(entry.get("subject_id"))
        if target:
            subject_descriptor = {
                "mediaType": target["manifest"]["mediaType"],
                "digest": target["digest"],
                "size": target["size"],
            }
        else:
            subject_descriptor = {
                "mediaType": MANIFEST_MEDIA_TYPE,
                "digest": entry["subject_digest"],
                "size": 512,
            }

        manifest = {
            "schemaVersion": 2,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "artifactType": entry["artifact_type"],
            "config": EMPTY_DESCRIPTOR,
            "layers": [EMPTY_DESCRIPTOR],
            "subject": subject_descriptor,
        }
        referrer = {
            **entry,
            "manifest": manifest,
            "digest": content_digest(manifest),
            "size": len(canonical_bytes(manifest)),
            "kind": "referrer",
        }
        referrers[entry["id"]] = referrer
        objects[(entry["repository"], referrer["digest"])] = referrer
    return subjects, referrers


def validate_mapping(subjects: dict, referrers: dict) -> list[str]:
    problems = []
    by_repository_and_digest = {
        (subject["repository"], subject["digest"]): subject
        for subject in subjects.values()
    }
    for referrer in referrers.values():
        subject_descriptor = referrer["manifest"].get("subject")
        key = (referrer["repository"], subject_descriptor.get("digest"))
        target = by_repository_and_digest.get(key)
        if target is None:
            problems.append(f"orphan:{referrer['id']}:{subject_descriptor['digest']}")
            continue
        expected = {
            "mediaType": target["manifest"]["mediaType"],
            "digest": target["digest"],
            "size": target["size"],
        }
        if subject_descriptor != expected:
            problems.append(f"descriptor-mismatch:{referrer['id']}")
    return problems


def age(created_day: int, now_day: int) -> int:
    return now_day - created_day


def unsafe_decisions(subjects: dict, referrers: dict, policy: dict, now_day: int) -> tuple[list[str], list[str]]:
    mapping_problems = validate_mapping(subjects, referrers)
    deletions = []
    premature = []
    linked_subject_ids = {
        referrer.get("subject_id")
        for referrer in referrers.values()
        if referrer.get("subject_id") in subjects
    }
    for referrer in referrers.values():
        if age(referrer["created_day"], now_day) >= policy["referrer_retention_days"]:
            deletions.append(referrer["id"])
            subject_id = referrer.get("subject_id")
            if subject_id in linked_subject_ids and age(
                subjects[subject_id]["created_day"], now_day
            ) < policy["subject_retention_days"]:
                premature.append(f"premature-expiry:{referrer['id']}")
    for subject in subjects.values():
        if age(subject["created_day"], now_day) >= policy["subject_retention_days"]:
            deletions.append(subject["id"])
    return mapping_problems, premature + [f"would-delete:{item}" for item in deletions]


def cohort_decisions(subjects: dict, referrers: dict, policy: dict, now_day: int) -> tuple[list[str], list[list[str]]]:
    if policy.get("retirement_mode") != "cohort":
        raise ValueError("corrected policy must use cohort retirement")
    if policy.get("retirement_order") != "referrers-before-subject":
        raise ValueError("corrected policy must retire referrers before the subject")
    mapping_problems = validate_mapping(subjects, referrers)
    plans = []
    for subject in subjects.values():
        cohort = [
            referrer
            for referrer in referrers.values()
            if referrer.get("subject_id")
            == next((key for key, value in subjects.items() if value is subject), None)
        ]
        subject_age = age(subject["created_day"], now_day)
        subject_retained = subject_age < policy["subject_retention_days"]
        refs_eligible = all(
            age(referrer["created_day"], now_day)
            >= max(
                policy["referrer_retention_days"],
                policy["subject_retention_days"]
                if policy.get("referrers_inherit_subject_expiry")
                else 0,
            )
            for referrer in cohort
        )
        if subject_retained or not refs_eligible:
            continue
        plans.append(
            [referrer["id"] for referrer in sorted(cohort, key=lambda item: item["id"])]
            + [subject["id"]]
        )
    return mapping_problems, plans


def run(lab):
    fixtures = read_json("fixtures.json")
    unsafe_policy = read_json("policy-unsafe.json")
    corrected_policy = read_json("policy-corrected.json")
    subjects, referrers = build_store(fixtures)

    red_mapping, red_decisions = unsafe_decisions(
        subjects, referrers, unsafe_policy, fixtures["evaluation_day"]
    )
    detects_orphan = len(red_mapping) == 1 and red_mapping[0].startswith("orphan:")
    detects_expiry = any(item.startswith("premature-expiry:") for item in red_decisions)
    lab.check("red", "Independent expiry allows premature deletion and the inventory finds an orphan",
              detects_orphan and detects_expiry,
              {"orphan_findings": red_mapping, "independent_retirement_decisions": red_decisions})

    valid_referrers = {
        key: value for key, value in referrers.items() if value.get("subject_id") in subjects
    }
    corrected_mapping, _ = cohort_decisions(
        subjects, referrers, corrected_policy, fixtures["evaluation_day"]
    )
    orphan_holds = (
        bool(corrected_mapping)
        and corrected_policy.get("orphan_action") == "hold-and-report"
    )
    green_mapping, early_plans = cohort_decisions(
        subjects, valid_referrers, corrected_policy, fixtures["evaluation_day"]
    )
    _, retirement_plans = cohort_decisions(
        subjects, valid_referrers, corrected_policy, fixtures["retirement_day"]
    )
    lab.check("green", "Digest-linked metadata remains retained and unmatched evidence is held",
              orphan_holds and not green_mapping and not early_plans,
              {"unresolved_metadata_held": orphan_holds, "no_retirement_while_subject_retained": not early_plans})
    expected_retirement = [["sbom", "signature-metadata", "worker-image"]]
    lab.check("positive", "Eligible fixture retirement includes all linked manifests in order",
              retirement_plans == expected_retirement, {"retirement_plan": retirement_plans})
    runpy.run_path(str(CASE_DIR / "registry_probe.py"))["run_registry"](lab)
    runpy.run_path(str(CASE_DIR / "co_retention.py"))["run_registry_evidence"](lab)
