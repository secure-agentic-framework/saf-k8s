"""Deterministic approval-policy fixture using invented records and labels only."""

import hashlib
import json
from pathlib import Path
import sys


DATASET_ID = "garden-card-demo"
DATASET_VERSION = "v4"
LABELS = {"sprout", "stone"}
CANONICAL_ASSETS = {
    "card-01": "two-green-marks", "card-02": "single-green-mark",
    "card-03": "two-gray-marks", "card-04": "single-gray-mark",
    "card-05": "one-green-one-gray",
}
DATASET_DIGEST = hashlib.sha256(
    json.dumps(CANONICAL_ASSETS, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
EXPECTED_BATCH = {"dataset_id": DATASET_ID, "version": DATASET_VERSION, "sha256": DATASET_DIGEST}
AUTHORIZED_ADJUDICATORS = {"curator-1": "label-adjudicator"}


def review(review_id, reviewer, asset_id, label):
    return {
        "review_id": review_id,
        "reviewer": reviewer,
        "asset_id": asset_id,
        "dataset_id": DATASET_ID,
        "dataset_version": DATASET_VERSION,
        "dataset_sha256": DATASET_DIGEST,
        "label": label,
    }


def demo_records():
    """Return fully synthetic review, correction and administrative QA records."""
    records = [
        {
            "asset_id": "card-01",
            "reviews": [review("rev-01a", "reviewer-amber", "card-01", "sprout"),
                        review("rev-01b", "reviewer-blue", "card-01", "sprout")],
            "correction": None,
            "qa": {"expected_queue": "desk-west-2", "observed_queue": "desk-west-2"},
        },
        {
            "asset_id": "card-02",
            "reviews": [review("rev-02a", "reviewer-amber", "card-02", "stone"),
                        review("rev-02b", "reviewer-coral", "card-02", "sprout")],
            "correction": {
                "actor": "curator-1",
                "role": "label-adjudicator",
                "authorized_role": AUTHORIZED_ADJUDICATORS["curator-1"],
                "final_label": "sprout",
                "reason": "rubric example adjudicated",
                "supersedes_review_ids": ["rev-02a", "rev-02b"],
                "dataset_id": DATASET_ID,
                "dataset_version": DATASET_VERSION,
                "dataset_sha256": DATASET_DIGEST,
            },
            "qa": {"expected_queue": "desk-west-2", "observed_queue": "desk-west-2"},
        },
        {
            "asset_id": "card-03",
            "reviews": [review("rev-03a", "reviewer-blue", "card-03", "stone"),
                        review("rev-03b", "reviewer-coral", "card-03", "stone")],
            "correction": None,
            # A benign queue-reference transcription discrepancy; label review is valid.
            "qa": {"expected_queue": "desk-west-2", "observed_queue": "desk-west-3"},
        },
    ]

    records.extend([
        {"asset_id": "card-04", "reviews": [
            review("rev-04a", "reviewer-amber", "card-04", "stone"),
            {**review("rev-04b", "reviewer-coral", "card-04", "stone"), "dataset_version": "v3"},
         ], "correction": None, "qa": {"expected_queue": "desk-west-2", "observed_queue": "desk-west-2"}},
        {"asset_id": "card-05", "reviews": [
            review("rev-05a", "reviewer-blue", "card-05", "sprout"),
            review("rev-05b", "reviewer-blue", "card-05", "sprout"),
         ], "correction": None, "qa": {"expected_queue": "desk-west-2", "observed_queue": "desk-west-2"}},
    ])
    return records


def evaluate(records=None):
    records = demo_records() if records is None else records
    results = []
    agreement_count = 0
    for record in records:
        reviews = record["reviews"]
        binding_ok = all(
            row["asset_id"] == record["asset_id"]
            and row["dataset_id"] == EXPECTED_BATCH["dataset_id"]
            and row["dataset_version"] == EXPECTED_BATCH["version"]
            and row["dataset_sha256"] == EXPECTED_BATCH["sha256"]
            for row in reviews
        )
        reviewer_ids = [row["reviewer"] for row in reviews]
        independent_review_ok = len(reviewer_ids) >= 2 and len(set(reviewer_ids)) >= 2
        labels_valid = all(row["label"] in LABELS for row in reviews)
        agreement = bool(reviews) and len({row["label"] for row in reviews}) == 1
        agreement_count += int(agreement)
        correction = record["correction"]
        correction_ok = bool(
            correction
            and correction["actor"] not in reviewer_ids
            and correction["role"] == "label-adjudicator"
            and AUTHORIZED_ADJUDICATORS.get(correction["actor"]) == correction["authorized_role"]
            and correction["authorized_role"] == correction["role"]
            and correction["dataset_id"] == EXPECTED_BATCH["dataset_id"]
            and correction["dataset_version"] == EXPECTED_BATCH["version"]
            and correction["dataset_sha256"] == EXPECTED_BATCH["sha256"]
            and set(correction["supersedes_review_ids"]) == {row["review_id"] for row in reviews}
            and bool(correction["reason"])
            and correction["final_label"] in LABELS
        )
        qa_ok = record["qa"]["expected_queue"] == record["qa"]["observed_queue"]
        label_resolved = labels_valid and (agreement or correction_ok)
        approved = binding_ok and independent_review_ok and label_resolved and qa_ok
        if approved:
            status, hold_reason = "approved", None
            final_label = correction["final_label"] if correction_ok else reviews[0]["label"]
        elif not binding_ok:
            status, hold_reason, final_label = "held", "dataset_binding_mismatch", None
        elif not independent_review_ok:
            status, hold_reason, final_label = "held", "minimum_independent_review_not_met", None
        elif not label_resolved:
            status, hold_reason, final_label = "held", "unresolved_review_disagreement", None
        else:
            status, hold_reason, final_label = "held", "administrative_qa_reference_mismatch", None
        results.append({
            "asset_id": record["asset_id"],
            "status": status,
            "hold_reason": hold_reason,
            "dataset_binding_ok": binding_ok,
            "independent_review_ok": independent_review_ok,
            "review_agreement": agreement,
            "authorized_correction": correction_ok,
            "correction_audit": ({
                "actor": correction["actor"],
                "role": correction["role"],
                "supersedes_review_ids": correction["supersedes_review_ids"],
                "reason": correction["reason"],
            } if correction_ok else None),
            "admin_qa_ok": qa_ok,
            "final_label": final_label,
        })
    return {
        "dataset_binding": {**EXPECTED_BATCH, "all_review_records_match": all(
            row["dataset_binding_ok"] for row in results)},
        "policy": {"minimum_independent_reviewers": 2, "authorized_adjudicator_role": "label-adjudicator"},
        "rows": results,
        "summary": {
            "approved_count": sum(row["status"] == "approved" for row in results),
            "held_count": sum(row["status"] == "held" for row in results),
            "raw_pair_agreement_count": agreement_count,
            "raw_pair_agreement_denominator": len(results),
            "raw_pair_agreement_is_not_an_approval_decision": True,
        },
    }


def main():
    root = Path("/release")
    if sys.argv[1] == "inspect":
        observed = {key: json.loads((root / (key + ".json")).read_text())
                    for key in ("unchecked", "governed")}
        print(json.dumps(observed, sort_keys=True))
        return
    records = json.loads(Path("/reviews/records.json").read_text())
    decision = evaluate(records)
    baseline = {row["asset_id"]: row["reviews"][0]["label"] for row in records}
    governed = {row["asset_id"]: row["final_label"] for row in decision["rows"]
                if row["status"] == "approved"}
    for name, approved in (("unchecked", baseline), ("governed", governed)):
        (root / (name + ".json")).write_text(json.dumps({
            "dataset": EXPECTED_BATCH, "labels": approved
        }, sort_keys=True) + "\n")
    print(json.dumps(decision, sort_keys=True))


if __name__ == "__main__":
    main()
