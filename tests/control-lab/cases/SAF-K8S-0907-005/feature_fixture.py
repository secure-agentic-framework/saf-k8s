"""Fixed, invented records and deterministic feature publication rules."""
from datetime import datetime, timezone


CUTOFF = "2026-05-01T00:00:00Z"
TARGET_CODES = {"cobalt": 0, "saffron": 1}

# Top-level subject_id is raw source metadata and is intentionally absent from
# the published feature document. Candidate defects are isolated one at a time.
RECORDS = {
    "valid": {
        "row_id": "row-amber-001",
        "subject_id": "invented-subject-17",
        "event_time": "2026-04-30T23:59:59Z",
        "target": "saffron",
        "features": {"signal_mean": 0.375, "context_count": 4},
    },
    "direct-id": {
        "row_id": "row-amber-002",
        "subject_id": "invented-subject-23",
        "event_time": "2026-04-30T23:59:58Z",
        "target": "cobalt",
        "features": {"subject_id": "invented-subject-23", "signal_mean": 0.25},
    },
    "target-derived": {
        "row_id": "row-amber-003",
        "subject_id": "invented-subject-41",
        "event_time": "2026-04-30T23:59:57Z",
        "target": "saffron",
        "features": {"signal_mean": 0.5, "target_code": 1},
    },
    "after-cutoff": {
        "row_id": "row-amber-004",
        "subject_id": "invented-subject-52",
        "event_time": "2026-05-01T00:00:01Z",
        "target": "cobalt",
        "features": {"signal_mean": 0.625},
    },
}

EXPECTED_OUTPUT = {
    "valid": {
        "event_time": "2026-04-30T23:59:59Z",
        "target": "saffron",
        "features": {"signal_mean": 0.375, "context_count": 4},
    }
}


def validate_and_transform(record):
    """Return (output, reason); no identifier or audit data is returned."""
    features = record["features"]
    if "subject_id" in features:
        return None, "direct-identifier-feature"
    if "target_code" in features and features["target_code"] == TARGET_CODES[record["target"]]:
        return None, "deterministic-target-derived-feature"
    fields = {"signal_mean": (float, int), "context_count": (int,)}
    if ("signal_mean" not in features or not features.keys() <= fields.keys()
            or any(type(value) not in fields[key] for key, value in features.items())):
        return None, "invalid-feature-schema"
    event_time = datetime.fromisoformat(record["event_time"].replace("Z", "+00:00"))
    cutoff = datetime.fromisoformat(CUTOFF.replace("Z", "+00:00"))
    if event_time.tzinfo != timezone.utc or event_time >= cutoff:
        return None, "temporal-cutoff"
    return {
        "event_time": record["event_time"],
        "target": record["target"],
        "features": dict(sorted(features.items())),
    }, None
