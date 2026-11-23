"""Pure deterministic privacy fixture logic; all records are fabricated."""
import hashlib
import json

APPROVED = {
    "dataset_id": "fixture-training-approved-v1",
    "classification": "internal-synthetic",
    "approval": "approved-training-v1",
    "rows": [
        {
            "fixture_row_key": "row-fixture-001",
            "fictional_full_name": "Fictional Person Alder",
            "fictional_contact": "alder-17@example.invalid",
            "feature_signal_a": 0.25,
            "feature_signal_b": "fixture-blue",
            "training_label": "fixture-class-1",
        },
        {
            "fixture_row_key": "row-fixture-002",
            "fictional_full_name": "Fictional Person Birch",
            "fictional_contact": "birch-29@example.invalid",
            "feature_signal_a": 0.75,
            "feature_signal_b": "fixture-green",
            "training_label": "fixture-class-2",
        },
    ],
}
BAD = {
    "dataset_id": "fixture-training-held-v1",
    "classification": "restricted-synthetic-unapproved",
    "approval": "not-approved",
    "rows": [
        {
            "fictional_full_name": "Fictional Person Cedar",
            "fictional_contact": "cedar-41@example.invalid",
            "feature_signal_a": 0.5,
            "training_label": "fixture-class-3",
        }
    ],
}
DIRECT_IDENTIFIER_FIELDS = ("fictional_full_name", "fictional_contact")
FEATURE_FIELDS = ("feature_signal_a", "feature_signal_b", "training_label")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def classify(dataset):
    if (dataset.get("dataset_id") == APPROVED["dataset_id"]
            and dataset.get("approval") == "approved-training-v1"
            and dataset.get("classification") == "internal-synthetic"):
        return "approved-for-fixture-training"
    return "hold-for-review"


def sanitize(dataset):
    if classify(dataset) != "approved-for-fixture-training":
        return None
    rows = []
    for source in dataset["rows"]:
        rows.append({key: source[key] for key in FEATURE_FIELDS if key in source})
    return {"dataset_id": dataset["dataset_id"], "classification": "internal-synthetic",
            "schema": "fixture-training-output-v1", "rows": rows}


def receipt(dataset, output):
    state = classify(dataset)
    return {
        "schema": "saf-k8s-0907-002-receipt-v1",
        "dataset_id": dataset["dataset_id"],
        "classification": dataset["classification"],
        "decision": state,
        "input_sha256": digest(dataset),
        "output_sha256": digest(output) if output is not None else None,
        "row_count": len(output["rows"]) if output is not None else 0,
        "removed_field_names": list(DIRECT_IDENTIFIER_FIELDS) if output is not None else [],
        "direct_identifier_values_recorded": False,
    }
