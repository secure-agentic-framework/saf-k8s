"""One-time revocation of a bound, inert break-glass approval record."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


NS = "saf-test"
RECORD = "saf-0602-007-review"
REVOCATION = "saf-0602-007-revocation"
POLICY = "saf-0602-007-revocation-integrity"
BINDING = "saf-0602-007-revocation-integrity"
MESSAGE = "only the designated reviewer may revoke this bound record once"
SECURITY = "system:serviceaccount:saf-test:saf-security"
OPERATIONS = "system:serviceaccount:saf-test:saf-operations"
REQUESTER = "system:serviceaccount:saf-test:saf-requester"
CURRENT_TIME = "2032-01-01T00:14:59Z"


def _apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))


def _get(lab, name):
    return json.loads(lab.kubectl("-n", NS, "get", "configmap", name, "-o", "json").stdout)


def _fingerprint(data):
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _patch(lab, actor, state, *, dry=False):
    flags = ["--dry-run=server"] if dry else []
    return lab.kubectl(f"--as={actor}", "-n", NS, "patch", "configmap", REVOCATION,
                       "--type=merge", "-p", json.dumps({"data": {"state": state}}),
                       *flags, "-o", "json", allow_failure=True)


def _rejected(result):
    return result.returncode != 0 and POLICY in result.stderr and MESSAGE in result.stderr


def _consumer(path, record, revocation, request, evaluated_at):
    payload = {"record": record, "revocation": revocation,
               "request": request, "evaluatedAt": evaluated_at}
    result = subprocess.run([sys.executable, str(path)], input=json.dumps(payload), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5, check=False)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        return None


def _install_policy(lab):
    rules = [{"apiGroups": [""], "resources": ["configmaps"],
              "resourceNames": [REVOCATION], "verbs": ["get", "patch"]}]
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "saf-0602-007-revocation-reviewer", "namespace": NS},
                "rules": rules})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "saf-0602-007-revocation-reviewer", "namespace": NS},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "saf-0602-007-revocation-reviewer"},
                "subjects": [{"kind": "ServiceAccount", "name": "saf-security", "namespace": NS},
                             {"kind": "ServiceAccount", "name": "saf-operations", "namespace": NS}]})

    immutable = " && ".join(
        f"object.data['{field}'] == oldObject.data['{field}']"
        for field in ("requestId", "targetDigest", "expiresAt", "approvalFingerprint")
    )
    expression = (
        f"size(object.data) == 5 && size(oldObject.data) == 5 && {immutable} "
        "&& object.metadata.labels == oldObject.metadata.labels "
        "&& object.metadata.annotations == oldObject.metadata.annotations "
        "&& ((oldObject.data['state'] == 'active' && object.data['state'] == 'active') "
        "|| (oldObject.data['state'] == 'revoked' && object.data['state'] == 'revoked') "
        f"|| (request.userInfo.username == '{SECURITY}' "
        "&& oldObject.data['state'] == 'active' && object.data['state'] == 'revoked'))"
    )
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": POLICY},
                "spec": {
                    "failurePolicy": "Fail",
                    "matchConstraints": {"resourceRules": [{
                        "apiGroups": [""], "apiVersions": ["v1"],
                        "operations": ["UPDATE"], "resources": ["configmaps"]}]},
                    "matchConditions": [{"name": "owned-revocation-record",
                        "expression": f"request.namespace == '{NS}' && request.name == '{REVOCATION}'"}],
                    "validations": [{"expression": expression, "message": MESSAGE,
                                     "reason": "Forbidden"}],
                }})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": BINDING},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"]}})


def run(lab, case_dir):
    approved_obj = _get(lab, RECORD)
    approved = approved_obj.get("data", {})
    expected_approved = {
        "requestId": "saf-0602-007-synthetic-request",
        "targetDigest": "sha256:" + "a" * 64,
        "expiresAt": "2032-01-01T00:15:00Z",
        "security": "approved", "operations": "approved",
    }
    if approved != expected_approved:
        lab.block("The existing approved inert record did not match the fixed revocation case")
    approval_fingerprint = _fingerprint(approved)
    revocation_data = {
        "requestId": approved["requestId"],
        "targetDigest": approved["targetDigest"],
        "expiresAt": approved["expiresAt"],
        "approvalFingerprint": approval_fingerprint,
        "state": "active",
    }
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": REVOCATION, "namespace": NS,
                              "labels": {"saf-k8s.example/0602-007": "inert-revocation"}},
                 "data": revocation_data})
    _install_policy(lab)

    request = {"requestId": approved["requestId"], "targetDigest": approved["targetDigest"]}
    consumer = Path(case_dir) / "revocation_consumer.py"
    before_obj = _get(lab, REVOCATION)
    before_record = before_obj.get("data", {})
    before_rv = before_obj.get("metadata", {}).get("resourceVersion")
    before_uid = before_obj.get("metadata", {}).get("uid")
    initial_state_exact = before_record == revocation_data
    current_verdict = _consumer(consumer, approved, before_record, request, CURRENT_TIME)

    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        readiness_probe = _patch(lab, OPERATIONS, "revoked", dry=True)
        if _rejected(readiness_probe):
            break
        time.sleep(0.5)
    else:
        lab.block("The revocation admission policy did not become effective")

    wrong_role = _patch(lab, OPERATIONS, "revoked")
    unauthorized_denied = _rejected(wrong_role)
    after_wrong_role = _get(lab, REVOCATION)
    wrong_role_preserved = after_wrong_role.get("data", {}) == revocation_data

    authorized = _patch(lab, SECURITY, "revoked")
    after_obj = _get(lab, REVOCATION)
    after_record = after_obj.get("data", {})
    after_approval = _get(lab, RECORD).get("data", {})
    after_uid = after_obj.get("metadata", {}).get("uid")
    after_rv = after_obj.get("metadata", {}).get("resourceVersion")
    post_verdict = _consumer(consumer, approved, after_record, request, CURRENT_TIME)

    restore = _patch(lab, SECURITY, "active")
    restore_denied = _rejected(restore)
    final_record = _get(lab, REVOCATION).get("data", {})
    final_approval = _get(lab, RECORD).get("data", {})

    unchanged_binding = (after_record == {**revocation_data, "state": "revoked"}
                         and after_uid == before_uid and after_rv != before_rv)
    approval_unchanged = (after_approval == approved and final_approval == approved
                          and _fingerprint(final_approval) == approval_fingerprint)
    passed = (initial_state_exact
              and current_verdict == {"permitted": True, "reason": "approved-unexpired"}
              and unauthorized_denied and wrong_role_preserved
              and authorized.returncode == 0
              and post_verdict == {"permitted": False, "reason": "revoked"}
              and restore_denied and final_record == after_record
              and unchanged_binding and approval_unchanged)

    evidence = {
        "scope": "Owned inert ConfigMap revocation state bound to one previously approved synthetic request; fixed consumer time input only.",
        "policy": POLICY, "binding": BINDING, "validation_actions": ["Deny"],
        "designated_reviewer": SECURITY,
        "wrong_reviewer": OPERATIONS,
        "approval_uid": approved_obj.get("metadata", {}).get("uid"),
        "approval_fingerprint": approval_fingerprint,
        "approval_data_before_and_after_unchanged": approval_unchanged,
        "revocation_uid_before_and_after": [before_uid, after_uid],
        "revocation_resource_versions": [before_rv, after_rv],
        "revocation_data_before": before_record,
        "initial_state_matches_independent_api_readback": initial_state_exact,
        "revocation_data_after": after_record,
        "wrong_reviewer_denied": unauthorized_denied,
        "wrong_reviewer_denial_preserved_state": wrong_role_preserved,
        "authorized_revocation_applied": authorized.returncode == 0,
        "consumer_before_revocation": current_verdict,
        "consumer_after_revocation": post_verdict,
        "revocation_restore_denied": restore_denied,
        "restore_denial_preserved_state": final_record == after_record,
        "time_source": "fixed-fixture-input",
        "trusted_time_enforced": False,
        "durable_audit_backend_observed": False,
        "image_or_pod_admission_performed": False,
        "provider_or_external_service_contacted": False,
    }
    (lab.evidence / "revocation-lifecycle.raw.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("positive",
              "Only the designated reviewer can revoke the exact approved record, the consumer denies it afterward, and revocation cannot be restored",
              passed,
              {"independent_revocation_readback_matches_fixture": initial_state_exact,
               "current_exact_request_allowed_before_revocation":
                   current_verdict == {"permitted": True, "reason": "approved-unexpired"},
               "wrong_reviewer_denied_without_state_change": unauthorized_denied and wrong_role_preserved,
               "authorized_revocation_persisted": authorized.returncode == 0 and unchanged_binding,
               "same_request_denied_after_revocation":
                   post_verdict == {"permitted": False, "reason": "revoked"},
               "revocation_restore_denied": restore_denied and final_record == after_record,
               "approval_record_unchanged": approval_unchanged,
               "trusted_time_or_audit_backend_claimed": False,
               "raw_evidence": "revocation-lifecycle.raw.json"})
