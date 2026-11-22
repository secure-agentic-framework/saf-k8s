"""Generate only fictional, hash-linked custody observations for the lab."""
import hashlib
import json
from pathlib import Path


ROOT = Path("/case")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def append_event(events, *, event_id, action, source, destination, authorization,
                 transfer_id=None, requested_destination=None, outcome="completed",
                 reason=None, timestamp):
    previous = events[-1]["event_sha256"] if events else "GENESIS"
    event = {
        "event_id": event_id,
        "sequence": len(events) + 1,
        "timestamp": timestamp,
        "timestamp_is_synthetic": True,
        "fixture_id": CASE["fixture_id"],
        "artifact_sha256": CASE["artifact_sha256"],
        "action": action,
        "from_label": source,
        "to_label": destination,
        "requested_to_label": requested_destination or destination,
        "authorization_label": authorization["authorization_label"],
        "authorization_status": authorization["authorization_status"],
        "approver_role_label": authorization["approver_role_label"],
        "authorization_scope_label": authorization["scope_label"],
        "outcome": outcome,
        "transfer_id": transfer_id,
        "reason": reason,
        "previous_event_sha256": previous,
    }
    event["event_sha256"] = digest(canonical(event))
    events.append(event)
    return event


def initial_events():
    events = []
    append_event(
        events, event_id="SYN-EVENT-COLLECT-001", action="collect-fixture",
        source="urn:example:origin:fixture", destination="urn:example:case:collection",
        authorization=CASE["collection_authorization"], timestamp="2030-01-01T11:58:00Z",
    )
    append_event(
        events, event_id="SYN-EVENT-SEAL-001", action="store-in-immutable-configmap",
        source="urn:example:case:collection", destination=CASE["transfer"]["from_label"],
        authorization=CASE["collection_authorization"], timestamp="2030-01-01T11:59:00Z",
    )
    return events


def verify_chain(events):
    previous = "GENESIS"
    valid = True
    for index, original in enumerate(events, start=1):
        event = dict(original)
        claimed = event.pop("event_sha256")
        valid = valid and event["sequence"] == index
        valid = valid and event["previous_event_sha256"] == previous
        valid = valid and event["artifact_sha256"] == CASE["artifact_sha256"]
        valid = valid and digest(canonical(event)) == claimed
        previous = claimed
    return valid


def transfer_scenario(*, gate_enabled, authorization):
    transfer = CASE["transfer"]
    events = initial_events()
    approved = (
        authorization.get("authorization_status") == "approved"
        and authorization.get("approver_role_label") == "synthetic-incident-commander"
        and authorization.get("scope_label") == f"transfer:{transfer['transfer_id']}"
        and authorization.get("authorization_label", "").startswith("urn:example:authorization:")
    )
    transfer_allowed = approved if gate_enabled else True
    if transfer_allowed:
        append_event(
            events, event_id="SYN-EVENT-TRANSFER-001", action="transfer-to-mock-review",
            source=transfer["from_label"], destination=transfer["to_label"],
            authorization=authorization, transfer_id=transfer["transfer_id"],
            requested_destination=transfer["to_label"],
            outcome="completed" if approved else "completed-without-approval-gate",
            reason=None if approved else "gate-disabled; pending authorization label ignored",
            timestamp=transfer["timestamp"],
        )
        state = "transferred"
    else:
        append_event(
            events, event_id="SYN-EVENT-TRANSFER-ATTEMPT-001", action="transfer-attempt-blocked",
            source=transfer["from_label"], destination=transfer["from_label"],
            authorization=authorization, transfer_id=transfer["transfer_id"],
            requested_destination=transfer["to_label"],
            outcome="blocked", reason="required approval label or scope is absent",
            timestamp=transfer["timestamp"],
        )
        state = "retained-in-immutable-storage"
    return {
        "transfer_id": transfer["transfer_id"],
        "gate_enabled": gate_enabled,
        "authorization": authorization,
        "state": state,
        "events": events,
        "chain_valid": verify_chain(events),
        "final_artifact_sha256": events[-1]["artifact_sha256"],
    }


CASE = json.loads((ROOT / "case.json").read_text(encoding="utf-8"))
artifact = (Path("/vault") / CASE["artifact_file"]).read_bytes()
observed_sha256 = digest(artifact)
if observed_sha256 != CASE["artifact_sha256"]:
    raise SystemExit("synthetic artifact SHA-256 does not match the case-pinned value")

without_gate = transfer_scenario(
    gate_enabled=False, authorization=CASE["transfer_authorization_pending"],
)
with_gate_pending = transfer_scenario(
    gate_enabled=True, authorization=CASE["transfer_authorization_pending"],
)
with_gate_approved = transfer_scenario(
    gate_enabled=True, authorization=CASE["transfer_authorization_approved"],
)

result = {
    "control_id": CASE["control_id"],
    "fixture_id": CASE["fixture_id"],
    "fixture_only": CASE["fixture_only"],
    "artifact_sha256_expected": CASE["artifact_sha256"],
    "artifact_sha256_observed": observed_sha256,
    "timestamps_are_synthetic": CASE["timestamps_are_synthetic"],
    "labels_are_credentials": CASE["labels_are_credentials"],
    "without_gate_pending_transfer": without_gate,
    "with_gate_pending_transfer": with_gate_pending,
    "with_gate_approved_transfer": with_gate_approved,
    "external_services_contacted": False,
}
print(json.dumps(result, sort_keys=True))
