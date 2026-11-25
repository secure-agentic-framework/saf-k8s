"""Verify reviewed emergency restoration access to a synthetic backup record."""

import json
from datetime import datetime, timezone
import time

SCOPE = (
    "Live Kubernetes authorization for emergency fixture records, with an explicitly modeled "
    "approval clock and sanitized lifecycle observation records. Invalid requester, operation "
    "and trigger candidates are checked before grant and against active-grant invariants."
)
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io"
ROLE = "fixture-temporary-backup-read"
SUBJECT = "fixture-emergency-operator"
REVIEWER = "fixture-recovery-approver"
TARGET = "fixture-restore-target"
NEIGHBOR = "fixture-restore-neighbor"
MARKER = "fixture backup marker"
AUDIT_REVIEWER = "fixture-recovery-reviewer"
LIFECYCLE_FILE = "emergency-backup-lifecycle-records.json"


def binding(lab, approval):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding",
                "metadata": {"name": ROLE, "annotations": {"fixture.example/approval": approval}},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": ROLE},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": SUBJECT}]})


def reconcile(lab, receipt, now, *, installed=False):
    valid = (receipt["requester"] == SUBJECT and receipt["reviewer"] == REVIEWER
             and receipt["target"] == TARGET and receipt["operation"] == "get"
             and receipt["trigger"] == "approved-recovery-exercise"
             and receipt["start"] <= now < receipt["expires"]
             and 0 < receipt["expires"] - receipt["start"] <= 20)
    if valid and not installed:
        binding(lab, receipt["id"])
    if installed and not valid:
        lab.kubectl("delete", "rolebinding", ROLE)
    return valid


def read(lab, name, *, subject=SUBJECT):
    return lab.kubectl("--as", subject, "get", "configmap", name, "-o", "json", allow_failure=True)


def read_many(lab, *, subject=SUBJECT):
    return lab.kubectl("--as", subject, "get", "configmaps", "-o", "json", allow_failure=True)


def api_outcome(result):
    if result.returncode == 0:
        return "allowed"
    if "Forbidden" in result.stderr:
        return "denied"
    return "other_failure"


def record_event(records, event_type, *, actor, target, operation, outcome,
                 approval_id, fixture_time=None, details=None):
    row = {
        "record_id": f"fixture-event-{len(records) + 1:02d}",
        "event_type": event_type,
        "actor": actor,
        "target": target,
        "operation": operation,
        "outcome": outcome,
        "approval_id": approval_id,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "time_basis": "fixture_clock" if fixture_time is not None else "observer_clock",
    }
    if fixture_time is not None:
        row["fixture_time"] = fixture_time
    if details:
        row.update(details)
    records.append(row)
    return row


def lifecycle_complete(records):
    kinds = {row["event_type"] for row in records}
    required = {"approval_decision", "authorized_access", "denied_access",
                "withdrawal", "independent_review"}
    required_fields = {"actor", "target", "operation", "outcome", "approval_id",
                       "observed_at_utc", "time_basis"}
    return (
        required <= kinds
        and all(required_fields <= set(row) for row in records)
        and all(row["time_basis"] in {"observer_clock", "fixture_clock"} for row in records)
        and any(row["event_type"] == "independent_review"
                and row.get("reviewer_independent") is True for row in records)
    )


def see(lab, expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = read(lab, TARGET)
        if expected and result.returncode == 0:
            return json.loads(result.stdout)["data"]["marker"] == MARKER
        if not expected and result.returncode != 0 and "Forbidden" in result.stderr:
            return True
        time.sleep(0.4)
    lab.block("The API did not converge to the expected backup marker authorization")


def run(lab):
    lifecycle = []
    for name in (TARGET, NEIGHBOR):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": True, "data": {"marker": MARKER}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET], "verbs": ["get"]}]})
    binding(lab, "fixture-unconditional-baseline")
    broad = see(lab, True)
    lab.kubectl("delete", "rolebinding", ROLE)
    initially_closed = see(lab, False)
    lab.check("red", "A standing grant exposes the marker without an active review", broad and initially_closed,
              {"standing_grant_readable": broad, "marker_closed_after_baseline": initially_closed})

    receipt = {"id": "fixture-exercise-01", "requester": SUBJECT, "reviewer": REVIEWER,
               "target": TARGET, "operation": "get", "trigger": "approved-recovery-exercise",
               "start": 20, "expires": 30}

    invalid_receipts = {
        "wrong_requester": dict(receipt, requester="fixture-unapproved-requester"),
        "wrong_operation": dict(receipt, operation="list"),
        "wrong_trigger": dict(receipt, trigger="unapproved-purpose"),
    }
    invalid_results = {}
    for label, candidate in invalid_receipts.items():
        accepted = reconcile(lab, candidate, 21)
        if label == "wrong_requester":
            actual_access = read(lab, TARGET, subject=candidate["requester"])
        elif label == "wrong_operation":
            actual_access = read_many(lab)
        else:
            actual_access = read(lab, TARGET)
        denied = api_outcome(actual_access) == "denied"
        invalid_results[label] = not accepted and denied
        record_event(
            lifecycle, "approval_decision", actor=candidate["requester"],
            target=candidate["target"], operation=candidate["operation"],
            outcome="rejected" if not accepted else "accepted",
            approval_id=candidate["id"], fixture_time=21,
            details={"reviewer": candidate["reviewer"], "trigger": candidate["trigger"],
                     "access_outcome": api_outcome(actual_access)},
        )
    denied = {
        "self_approval": not reconcile(lab, dict(receipt, reviewer=SUBJECT), 21),
        "wrong_target": not reconcile(lab, dict(receipt, target=NEIGHBOR), 21),
        "outside_window": not reconcile(lab, receipt, 19),
        "oversized_window": not reconcile(lab, dict(receipt, expires=60), 21),
        **invalid_results,
    }
    prior_closed = see(lab, False)
    lab.check("green", "The reviewed workflow withholds API access until scoped independent approval is current",
              all(denied.values()) and prior_closed, {**denied, "actual_access_closed": prior_closed})

    issued = reconcile(lab, receipt, 21)
    record_event(
        lifecycle, "approval_decision", actor=receipt["requester"],
        target=receipt["target"], operation=receipt["operation"], outcome="approved" if issued else "grant_unverified",
        approval_id=receipt["id"], fixture_time=21,
        details={"reviewer": receipt["reviewer"], "trigger": receipt["trigger"],
                 "grant_start": receipt["start"], "grant_expiry": receipt["expires"]},
    )
    intended = see(lab, True)
    actual_allowed = read(lab, TARGET)
    neighbor = read(lab, NEIGHBOR)
    scoped = neighbor.returncode != 0 and "Forbidden" in neighbor.stderr
    record_event(
        lifecycle, "authorized_access", actor=SUBJECT, target=TARGET, operation="get",
        outcome=api_outcome(actual_allowed), approval_id=receipt["id"], fixture_time=21,
        details={"api_status": {"allowed": 200, "denied": 403}.get(api_outcome(actual_allowed))},
    )
    record_event(
        lifecycle, "denied_access", actor=SUBJECT, target=NEIGHBOR, operation="get",
        outcome=api_outcome(neighbor), approval_id=receipt["id"], fixture_time=21,
        details={"api_status": 403 if api_outcome(neighbor) == "denied" else None},
    )

    active_invariants = {}
    for label, candidate in invalid_receipts.items():
        rejected = not reconcile(lab, candidate, 21)
        authorized_read = read(lab, TARGET)
        neighbor_read = read(lab, NEIGHBOR)
        if label == "wrong_requester":
            unauthorized_read = read(lab, TARGET, subject=candidate["requester"])
            unauthorized_outcome = api_outcome(unauthorized_read)
            event_type = "denied_access"
        elif label == "wrong_operation":
            unauthorized_read = read_many(lab)
            unauthorized_outcome = api_outcome(unauthorized_read)
            event_type = "denied_access"
        else:
            # The approved requester still has the original narrow grant; an
            # invalid second-purpose receipt must neither broaden nor revoke it.
            unauthorized_outcome = api_outcome(authorized_read)
            event_type = "approval_decision"
        active_invariants[label] = (
            rejected
            and api_outcome(authorized_read) == "allowed"
            and api_outcome(neighbor_read) == "denied"
            and ((label == "wrong_trigger" and unauthorized_outcome == "allowed")
                 or (label != "wrong_trigger" and unauthorized_outcome == "denied"))
        )
        record_event(
            lifecycle, event_type, actor=candidate["requester"], target=TARGET,
            operation=candidate["operation"], outcome=
            ("rejected" if rejected else "accepted") if label == "wrong_trigger" else unauthorized_outcome,
            approval_id=candidate["id"], fixture_time=21,
            details={"invalid_receipt": label,
                     "current_approved_subject_still_allowed": api_outcome(authorized_read) == "allowed",
                     "neighbor_still_denied": api_outcome(neighbor_read) == "denied"},
        )

    withdrawn = not reconcile(lab, receipt, 30, installed=True)
    expired_read = see(lab, False)
    actual_after_expiry = read(lab, TARGET)
    expired = withdrawn and expired_read and api_outcome(actual_after_expiry) == "denied"
    record_event(
        lifecycle, "withdrawal", actor="fixture-reconciler", target=TARGET,
        operation="get", outcome="withdrawn" if expired else "withdrawal_unverified",
        approval_id=receipt["id"], fixture_time=30,
        details={"subsequent_api_outcome": api_outcome(actual_after_expiry)},
    )

    reviewed_ids = [row["record_id"] for row in lifecycle]
    review_event = record_event(
        lifecycle, "independent_review", actor=AUDIT_REVIEWER, target=TARGET,
        operation="review", outcome="pending_review",
        approval_id=receipt["id"],
        details={"reviewer_independent": AUDIT_REVIEWER not in {receipt["requester"], receipt["reviewer"]},
                 "reviewed_record_ids": reviewed_ids,
                 "review_kind": "fixture_post_access_reconciliation"},
    )
    review_ok = (
        review_event["reviewer_independent"] is True
        and issued and intended and scoped and expired and all(active_invariants.values())
        and lifecycle_complete(lifecycle)
    )
    review_event["outcome"] = "reconciled" if review_ok else "review_failed"
    record_ok = lifecycle_complete(lifecycle) and review_ok
    (lab.evidence / LIFECYCLE_FILE).write_text(json.dumps(lifecycle, indent=2, sort_keys=True) + "\n")

    lab.check("positive", "A current approval permits only its fixture marker and expiry withdraws permission",
              issued and intended and scoped and expired and all(active_invariants.values()),
              {"reviewed_marker_readable": intended, "unrelated_marker_forbidden": scoped,
               "after_expiry_denied": expired,
               "invalid_receipts_do_not_expand_active_grant": active_invariants})

    lab.check("positive", "Sanitized lifecycle evidence retains approval, access, withdrawal and independent review",
              record_ok,
              {"lifecycle_record_complete": record_ok,
               "approval_access_denial_withdrawal_review_present": record_ok,
               "record_count": len(lifecycle), "raw_evidence_file": LIFECYCLE_FILE,
               "fixture_clock_labeled": all(
                   row["time_basis"] in {"observer_clock", "fixture_clock"} for row in lifecycle)})
    (lab.evidence / "emergency-backup-access-observations.json").write_text(json.dumps({
        "preapproval": denied, "active_scoped_read": issued and intended and scoped, "expired_access_denied": expired,
        "time_modeled": True, "repository_or_restore_tested": False,
        "lifecycle_record_file": LIFECYCLE_FILE,
    }, indent=2) + "\n")
