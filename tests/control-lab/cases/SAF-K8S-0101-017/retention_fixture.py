"""Compare authorized downstream event retention across a two-day cutoff."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

UTC = timezone.utc
RETENTION = timedelta(days=2)


def parse_time(value):
    if not value:
        raise ValueError("event timestamp missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event timestamp must include timezone")
    return parsed.astimezone(UTC)


def event_time(event):
    # Audit Event.stageTimestamp is the time the event stage occurred; retain
    # requestReceivedTimestamp only as a fallback for minimal synthetic fixtures.
    return parse_time(event.get("stageTimestamp") or event.get("requestReceivedTimestamp"))


def read_events(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_events(path, events):
    path = Path(path)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            for event in events:
                stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def prune(path, *, retention_clock, retention=RETENTION):
    """Prune only records strictly older than retention_clock - retention."""
    now = parse_time(retention_clock)
    cutoff = now - retention
    events = read_events(path)
    kept = [e for e in events if event_time(e) >= cutoff]
    removed = [e for e in events if event_time(e) < cutoff]
    write_events(path, kept)
    return {"cutoff": cutoff, "before": len(events), "kept": len(kept), "removed": len(removed)}


def query(path, audit_id):
    return [event for event in read_events(path) if event.get("auditID") == audit_id]


def synthetic_event(audit_id, timestamp):
    # Metadata-only benign event: no request/response object or user payload.
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event",
        "auditID": audit_id, "level": "Metadata", "stage": "ResponseComplete",
        "stageTimestamp": timestamp,
        "verb": "create", "objectRef": {"resource": "configmaps", "namespace": "saf-test",
                                           "name": "retention-fixture-marker"},
        "responseStatus": {"code": 201},
    }


def run_fixture(directory, *, retention_clock, live_events=()):
    """Seed boundary fixtures plus actual receiver events, prune, and preserve summary evidence."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = parse_time(retention_clock)
    cutoff = now - RETENTION
    iso = lambda d: d.isoformat(timespec="seconds").replace("+00:00", "Z")
    named = {
        "expired_before_cutoff": synthetic_event("fixture-expired", iso(cutoff - timedelta(seconds=1))),
        "exact_cutoff": synthetic_event("fixture-cutoff", iso(cutoff)),
        "inside_window": synthetic_event("fixture-inside", iso(cutoff + timedelta(seconds=1))),
        "recent": synthetic_event("fixture-recent", iso(now - timedelta(seconds=1))),
    }
    live = list(live_events)
    if not live:
        raise ValueError("a real selected audit event is required")
    if any("requestObject" in e or "responseObject" in e for e in live):
        raise ValueError("live API audit events must be metadata-only")
    if any(not e.get("auditID") for e in live):
        raise ValueError("live API audit event missing auditID")
    path = directory / "downstream-audit.jsonl"
    write_events(path, [*named.values(), *live])
    # Verify natural retrieval before retention and identify synthetic/live rows
    # by stable keys without returning event bodies in the evidence receipt.
    before = {key: len(query(path, event["auditID"])) == 1 for key, event in named.items()}
    live_ids = [event["auditID"] for event in live]
    live_before = all(len(query(path, audit_id)) == 1 for audit_id in live_ids)
    result = prune(path, retention_clock=iso(now))
    after = {key: len(query(path, event["auditID"])) == 1 for key, event in named.items()}
    live_after = all(len(query(path, audit_id)) == 1 for audit_id in live_ids)
    summary = {
        "fixture": "0101-017.1 local downstream retention companion",
        "retention_seconds": int(RETENTION.total_seconds()),
        "retention_clock_injected": True,
        "event_timestamps_modified": False,
        "live_api_audit_event_count": len(live),
        "live_event_retrieval_before_prune": live_before,
        "live_event_retrieval_after_prune": live_after,
        "synthetic_retrieval_before_prune": before,
        "synthetic_retrieval_after_prune": after,
        "expired_removed": not after["expired_before_cutoff"],
        "exact_cutoff_protected": after["exact_cutoff"],
        "inside_window_protected": after["inside_window"],
        "recent_protected": after["recent"],
        "counts": {"before": result["before"], "kept": result["kept"], "removed": result["removed"]},
        "raw_events_written_to_fixture_store": True,
        "receipt_contains_event_bodies_or_ids": False,
    }
    return summary
