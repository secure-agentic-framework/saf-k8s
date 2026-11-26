"""Correlate only synthetic workload and time scoped defensive context."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Fixture timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def scope(record):
    return record["cluster"], record["namespace"], record["workload_id"]


def correlated(event, records, window, review_time, authorized_source_classes):
    event_time = timestamp(event["observed_at"])
    matches = []
    for record in records:
        if record.get("source_class") not in authorized_source_classes:
            continue
        if scope(record) != scope(event):
            continue
        observed = timestamp(record["observed_at"])
        delta = abs((observed - event_time).total_seconds())
        if observed <= review_time and delta <= window:
            matches.append(record)
    return matches


def business_record(event, records):
    event_time = timestamp(event["observed_at"])
    exact = [row for row in records if scope(row) == scope(event)]
    valid = [row for row in exact
             if timestamp(row["valid_from"]) <= event_time <= timestamp(row["valid_until"])]
    if len(valid) == 1:
        return valid[0], "valid"
    if valid:
        return None, "ambiguous"
    return None, "expired" if exact else "missing"


def rank(fixtures, mode):
    if mode not in {"single-signal", "correlated"}:
        raise ValueError("unknown triage mode")
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    results = []
    window = fixtures["correlation_window_seconds"]
    review_time = timestamp(fixtures["review_time"])
    for event in fixtures["technical_events"]:
        context_matches = correlated(event, fixtures["nontechnical_context"], window, review_time,
                                     set(fixtures["authorized_source_classes"]))
        business, business_status = business_record(event, fixtures["business_context"])
        if mode == "single-signal":
            urgency = "urgent" if event["severity"] == "critical" else (
                "elevated" if event["severity"] == "high" else "routine")
            matched_context = []
            business = None
            business_status = "not_considered"
        else:
            context_raises_review = bool(
                context_matches and business and business["business_criticality"] == "high")
            urgency = ("urgent" if context_raises_review or event["severity"] == "critical" else
                       "elevated" if event["severity"] == "high" else "routine")
            matched_context = context_matches
        results.append({
            "event_id": event["event_id"],
            "workload_id": event["workload_id"],
            "observed_at": event["observed_at"],
            "technical_severity": event["severity"],
            "review_urgency": urgency,
            "matched_nontechnical_record_ids": sorted(row["record_id"] for row in matched_context),
            "business_context_record_id": business["record_id"] if business else None,
            "business_context_status": business_status,
            "analyst_review_recommended": urgency in {"urgent", "elevated"},
            "attribution": "not_assessed",
            "employment_decision": "not_applicable",
        })
    order = {"urgent": 0, "elevated": 1, "routine": 2}
    if mode == "single-signal":
        results.sort(key=lambda row: (-severity_order[row["technical_severity"]], row["event_id"]))
    else:
        results.sort(key=lambda row: (order[row["review_urgency"]],
                                      -severity_order[row["technical_severity"]], row["event_id"]))
    return results


if __name__ == "__main__":
    fixture = json.loads(Path("/fixture/fixtures.json").read_text())
    print(json.dumps(rank(fixture, sys.argv[1]), sort_keys=True))
