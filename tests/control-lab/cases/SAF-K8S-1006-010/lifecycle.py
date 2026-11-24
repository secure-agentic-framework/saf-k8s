"""Bounded, synthetic non-renewal and closure on the published consumer path."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

NS = "saf-test"
REVIEWER = "fixture-exception-renewal-reviewer"
CLOSER = "fixture-exception-closure-operator"
DECISION = "saf-lab-1006-010-renewal-decision"
RECORD = "exact-approved"
WORKLOAD_NAME = "saf-ai-exception-workload"
POLICY = "saf-lab-1006-010-runtime-exception"
DECISION_POLICY = "saf-lab-1006-010-lifecycle-decision"
BOUND_SECONDS = 180


def _admin(lab, *args, namespace=NS, timeout=40, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", namespace, f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, allow_failure=allow_failure, payload=payload,
    )


def _client(lab, config, *args, payload=None, allow_failure=True, timeout=35):
    return lab.command(
        "kubectl", "--kubeconfig", str(config), "--context", "fixture", "--namespace", NS,
        f"--request-timeout={timeout - 5}s", *args, timeout=timeout,
        allow_failure=allow_failure,
        payload=json.dumps(payload, separators=(",", ":")) if payload is not None else None,
    )


def _credential(lab, account):
    admin = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    token_result = subprocess.run(
        [*admin, "--namespace", NS, "create", "token", account, "--duration=10m"],
        text=True, capture_output=True, env=lab.env, timeout=25,
    )
    if token_result.returncode:
        lab.block(f"Could not mint short-lived token for {account}")
    token = token_result.stdout.strip()
    view = subprocess.run([*admin, "config", "view", "--minify", "--flatten", "--raw", "-o", "json"],
                          text=True, capture_output=True, env=lab.env, timeout=25)
    if view.returncode or not token or any(ch.isspace() for ch in token):
        lab.block(f"Could not construct fixture credentials for {account}")
    source = json.loads(view.stdout)["clusters"][0]["cluster"]
    config = {"apiVersion": "v1", "kind": "Config", "current-context": "fixture",
              "clusters": [{"name": "fixture", "cluster": {
                  "server": source["server"], "certificate-authority-data": source["certificate-authority-data"]}}],
              "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
              "users": [{"name": "fixture", "user": {"token": token}}]}
    path = lab.kubeconfig.with_name(account + "-credential")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(config, output)
    return path


def _identity(account):
    return f"system:serviceaccount:{NS}:{account}"


def _grant(lab, role, resource, verb, account, resource_name=None):
    rule = {"apiGroups": ["saf-lab.example"] if resource == "policyexceptions" else [""],
            "resources": [resource], "verbs": [verb]}
    if resource_name:
        rule["resourceNames"] = [resource_name]
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": role}, "rules": [rule]})
    lab.kubectl("create", "rolebinding", role, f"--role={role}",
                f"--serviceaccount={NS}:{account}")


def _server_time(lab, prefix):
    name = f"{prefix}-{uuid.uuid4().hex[:10]}"
    result = _admin(lab, "create", "configmap", name, "--from-literal=purpose=clock-sample", "-o", "json")
    stamp = json.loads(result.stdout)["metadata"].get("creationTimestamp")
    if not stamp or not stamp.endswith("Z"):
        lab.block("API server did not provide a UTC timestamp for lifecycle evidence")
    return stamp, datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _denied(result, policy, message):
    return result.returncode != 0 and "admission webhook" in result.stderr \
        and policy in result.stderr and message in result.stderr


def _rbac_refused(result, identity, verb, resource):
    return (result.returncode != 0
            and f'User "{identity}" cannot {verb} resource "{resource}"' in result.stderr)


def _dry_run(lab, config, workload):
    return _client(lab, config, "create", "-f", "-", "-o", "json", "--dry-run=server",
                   payload=workload)


def run(lab, approver, exact, workload):
    # Delete only the old, already-expired demonstration record. The original
    # expiry assertion and its UID/resourceVersion observation were written before
    # this lifecycle function is called.
    lab.kubectl("delete", "policyexceptions.saf-lab.example", RECORD, "--wait=true")
    for account in (REVIEWER, CLOSER):
        lab.kubectl("create", "serviceaccount", account)
    _grant(lab, "fixture-renewal-reviewer", "configmaps", "create", REVIEWER)
    _grant(lab, "fixture-renewal-decision-maintenance", "configmaps", "patch", REVIEWER, DECISION)
    _grant(lab, "fixture-renewal-decision-read", "configmaps", "get", REVIEWER, DECISION)
    _grant(lab, "fixture-closure-operator", "policyexceptions", "delete", CLOSER, RECORD)
    _grant(lab, "fixture-closure-decision-read", "configmaps", "get", CLOSER, DECISION)
    reviewer = _credential(lab, REVIEWER)
    closer = _credential(lab, CLOSER)

    reviewer_identity = _identity(REVIEWER)
    closer_identity = _identity(CLOSER)
    identity_results = {}
    for account, config in ((REVIEWER, reviewer), (CLOSER, closer)):
        who = _client(lab, config, "auth", "whoami", "-o", "json")
        identity_results[account] = (
            not who.returncode and
            json.loads(who.stdout)["status"]["userInfo"]["username"] == _identity(account))
    lab.check("positive", "The lifecycle reviewer and closure operator are separately authenticated",
              all(identity_results.values()), identity_results)

    # The reviewer can create only a decision object that passes this exact,
    # authenticated, immutable ConfigMap admission contract. Cluster administrators
    # retain their normal ability to create clock-sample ConfigMaps for the fixture.
    lab.apply(Path(__file__).with_name("lifecycle-decision-policy.yaml"))

    approver_decision = _client(lab, approver, "create", "configmap", DECISION,
                                "--from-literal=decision=close-no-renewal")
    approver_cannot_decide = _rbac_refused(
        approver_decision, _identity("fixture-exception-approver"), "create", "configmaps")
    lab.check("green", "The exception approver cannot author the renewal decision",
              approver_cannot_decide, {"approver_decision_forbidden": approver_cannot_decide})

    now_stamp, now = _server_time(lab, "lifecycle-approval-start")
    expiry = now + timedelta(seconds=BOUND_SECONDS)
    expires_at = expiry.isoformat(timespec="seconds").replace("+00:00", "Z")
    exception = json.loads(json.dumps(exact))
    exception["spec"]["expiresAt"] = expires_at
    created = _client(lab, approver, "create", "-f", "-", "-o", "json", payload=exception,
                      allow_failure=False)
    created_record = json.loads(created.stdout)
    record_ok = (created_record.get("metadata", {}).get("name") == RECORD
                 and created_record.get("spec") == exception["spec"])
    lab.check("positive", "The approver creates the exact, bounded exception for the real consumer",
              record_ok, {"record_exact": record_ok, "maximum_seconds": BOUND_SECONDS})
    active = _dry_run(lab, approver, workload)
    active_admitted = active.returncode == 0 and json.loads(active.stdout).get("kind") == "Deployment"
    lab.check("positive", "Kyverno admits the harmless dry-run while the renewed approval is active",
              active_admitted, {"consumer_admitted": active_admitted})

    reviewer_exception = json.loads(json.dumps(exception))
    reviewer_exception["spec"]["approval"]["approverIdentity"] = reviewer_identity
    reviewer_write = _client(lab, reviewer, "create", "-f", "-", "-o", "json",
                             payload=reviewer_exception)
    reviewer_cannot_approve = _rbac_refused(reviewer_write, reviewer_identity, "create", "policyexceptions")
    lab.check("green", "The renewal reviewer cannot create or approve PolicyException records",
              reviewer_cannot_approve, {"reviewer_exception_write_forbidden": reviewer_cannot_approve})

    reviewer_delete = _client(lab, reviewer, "delete", "policyexceptions.saf-lab.example", RECORD)
    reviewer_cannot_close = _rbac_refused(reviewer_delete, reviewer_identity, "delete", "policyexceptions")
    lab.check("green", "The reviewer cannot execute closure of the approved exception",
              reviewer_cannot_close, {"reviewer_delete_forbidden": reviewer_cannot_close})

    decision = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": DECISION, "namespace": NS},
        "immutable": True,
        "data": {
            "decision": "close-no-renewal",
            "recordName": RECORD,
            "recordUid": created_record["metadata"]["uid"],
            "policyRef": "ai-workload-compliance",
            "scopeNamespace": NS,
            "scopeKind": "Deployment",
            "scopeName": WORKLOAD_NAME,
            "deciderIdentity": reviewer_identity,
            "expiresAt": expires_at,
            "justification": "Synthetic review window closed; do not renew this fixture exception.",
        },
    }
    broad_decision = json.loads(json.dumps(decision))
    broad_decision["metadata"]["name"] = DECISION + "-broad"
    deadline = time.monotonic() + 25
    while True:
        broad_result = _client(lab, reviewer, "create", "-f", "-", "-o", "json", "--dry-run=server",
                               payload=broad_decision)
        if DECISION_POLICY in broad_result.stderr or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    broad_refused = (broad_result.returncode != 0 and DECISION_POLICY in broad_result.stderr
                     and "only the authenticated lifecycle reviewer" in broad_result.stderr)
    lab.check("green", "Admission refuses a decision record with a different object name",
              broad_refused, {"broad_decision_refused": broad_refused})

    wrong_scope = json.loads(json.dumps(decision))
    wrong_scope["data"]["scopeName"] = "another-workload"
    wrong_scope_result = _client(lab, reviewer, "create", "-f", "-", "-o", "json",
                                 payload=wrong_scope)
    wrong_scope_refused = (wrong_scope_result.returncode != 0
                           and DECISION_POLICY in wrong_scope_result.stderr
                           and "only the authenticated lifecycle reviewer" in wrong_scope_result.stderr)
    lab.check("green", "Admission refuses a renewal decision for any other workload scope",
              wrong_scope_refused, {"wrong_scope_decision_refused": wrong_scope_refused})

    premature = _client(lab, closer, "delete", "policyexceptions.saf-lab.example", RECORD,
                        "--dry-run=server", "--wait=false")
    no_decision_denied = premature.returncode != 0 and "saf-lab-1006-010-authorized-closure" in premature.stderr
    lab.check("green", "The authorized closer needs a retained decision for the exact exception",
              no_decision_denied, {"missing_closure_decision_refused": no_decision_denied})

    retained = _client(lab, reviewer, "create", "-f", "-", "-o", "json", payload=decision,
                       allow_failure=True)
    decision_admitted = retained.returncode == 0
    lab.check("positive", "The authenticated reviewer records an immutable, exact-scope no-renewal decision",
              decision_admitted, {"decision_admitted": decision_admitted,
                                  "decision_policy": DECISION_POLICY})
    retained_obj = json.loads(retained.stdout)
    decision_timestamp = retained_obj.get("metadata", {}).get("creationTimestamp")
    evidence_fields_match = (retained_obj.get("immutable") is True
                             and retained_obj.get("data") == decision["data"]
                             and decision_timestamp is not None)
    lab.check("positive", "The API retains reviewer identity, target UID, exact scope, bounded expiry and decision time",
              evidence_fields_match, {"retained_fields_match": evidence_fields_match})

    mutate = _client(lab, reviewer, "patch", "configmap", DECISION, "--type=merge",
                     "-p", '{"data":{"decision":"renew"}}')
    immutable = (mutate.returncode != 0 and "immutable" in mutate.stderr.lower())
    lab.check("green", "The retained decision evidence cannot be edited after creation",
              immutable, {"decision_immutable": immutable})

    closer_decision = _client(lab, closer, "create", "-f", "-", "-o", "json", payload=decision)
    closer_cannot_decide = _rbac_refused(closer_decision, closer_identity, "create", "configmaps")
    lab.check("green", "The closure operator cannot author or replace the renewal decision",
              closer_cannot_decide, {"closer_decision_forbidden": closer_cannot_decide})

    close = _client(lab, closer, "delete", "policyexceptions.saf-lab.example", RECORD,
                    "--wait=false", allow_failure=True)
    check_absent = _admin(lab, "get", "policyexceptions.saf-lab.example", RECORD, allow_failure=True)
    closed = close.returncode == 0 and check_absent.returncode != 0 and "(NotFound)" in check_absent.stderr
    lab.check("positive", "The separate closure operator deletes only the named approved exception",
              closed, {"closure_executed": closed, "authorized_resource_name": RECORD,
                       "operator_identity": closer_identity})
    after_close = _dry_run(lab, approver, workload)
    consumer_denied = _denied(after_close, POLICY,
                              "SAF-LAB-1006-010: scoped fixture exception is missing")
    lab.check("green", "Kyverno denies the same harmless request immediately after recorded closure",
              consumer_denied, {"consumer_denied_after_closure": consumer_denied})

    retained_after_close = json.loads(_admin(lab, "get", "configmap", DECISION, "-o", "json").stdout)
    decision_retained = (retained_after_close.get("immutable") is True
                         and retained_after_close.get("data") == decision["data"]
                         and retained_after_close.get("metadata", {}).get("creationTimestamp") == decision_timestamp)
    lab.check("positive", "The no-renewal decision remains retrievable after closure and consumer denial",
              decision_retained, {"decision_retained_after_close": decision_retained})

    (lab.evidence / "runtime-lifecycle-observations.json").write_text(json.dumps({
        "clock_anchor": "API-server assigned ConfigMap creation timestamps",
        "synthetic_bound_seconds": BOUND_SECONDS,
        "approval_start_utc": now_stamp,
        "approval_expiry_utc": expires_at,
        "reviewer_identity": reviewer_identity,
        "closure_operator_identity": closer_identity,
        "decision_name": DECISION,
        "decision_created_utc": decision_timestamp,
        "decision_record": decision["data"],
        "decision": "close-no-renewal",
        "target_record_uid": created_record["metadata"]["uid"],
        "exact_scope": {"policyRef": "ai-workload-compliance", "namespace": NS,
                        "kind": "Deployment", "name": WORKLOAD_NAME},
        "decision_immutable": immutable,
        "decision_retained_after_close": decision_retained,
        "consumer_admitted_before_closure": active_admitted,
        "consumer_missing_record_denial_after_closure": after_close.stderr.strip(),
        "consumer_denied_after_closure": consumer_denied,
        "operational_evidence_not_provided_by_fixture": [
            "real review scheduling and expiry monitoring",
            "approved accountable role roster and identity lifecycle",
            "production deployment and policy coverage review records",
            "production approval rationale and retained change/audit records",
        ],
    }, indent=2) + "\n")
