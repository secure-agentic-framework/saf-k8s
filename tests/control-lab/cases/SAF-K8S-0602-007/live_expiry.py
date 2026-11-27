"""Add a real-time, local-only expiry observation for a second inert record."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time

NS = "saf-test"
REVIEWERS = {"saf-security": "security", "saf-operations": "operations"}


def user(actor):
    return f"system:serviceaccount:{NS}:{actor}"

LIVE_RECORD = "saf-0602-007-live-expiry-review"
READINESS_RECORD = "saf-0602-007-live-expiry-policy-probe"
LIVE_POLICY = "saf-0602-007-live-expiry-guard"
LIVE_BINDING = LIVE_POLICY
LIVE_SA = "saf-0602-007-live-expiry-consumer"
LIVE_ROLE = "saf-0602-007-live-expiry-reader"
LIVE_CODE = "saf-0602-007-live-expiry-code"
LIVE_JOB = "saf-0602-007-live-expiry-observer"
LIVE_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
REQUEST_ID = "saf-0602-007-live-expiry-synthetic-request"
TARGET_DIGEST = "sha256:" + "c" * 64
WINDOW_SECONDS = 45
HOST_API_CLOCK_TOLERANCE_SECONDS = 5
JOB_HOST_CLOCK_TOLERANCE_SECONDS = 12


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def apply(lab, value):
    return lab.kubectl("apply", "-f", "-", payload=json.dumps(value))


def get_configmap(lab, name):
    return json.loads(lab.kubectl("-n", NS, "get", "configmap", name, "-o", "json").stdout)


def patch(lab, actor, name, values, *, dry=False):
    flags = ["--dry-run=server"] if dry else []
    return lab.kubectl(
        f"--as={user(actor)}", "-n", NS, "patch", "configmap", name,
        "--type=merge", "-p", json.dumps({"data": values}), *flags, "-o", "json",
        allow_failure=True)


def policy_denied(result):
    return (result.returncode != 0 and LIVE_POLICY in result.stderr
            and "only the designated reviewer can approve its own field on this exact record" in result.stderr)


def base_data(expiry):
    return {"requestId": REQUEST_ID, "targetDigest": TARGET_DIGEST,
            "expiresAt": expiry, "security": "pending", "operations": "pending"}


def install_guard(lab):
    choices = []
    for actor, vote in REVIEWERS.items():
        other = next(value for value in REVIEWERS.values() if value != vote)
        choices.append(
            f"(request.userInfo.username == '{user(actor)}' "
            f"&& oldObject.data['{vote}'] == 'pending' "
            f"&& object.data['{vote}'] == 'approved' "
            f"&& object.data['{other}'] == oldObject.data['{other}'])")
    immutable = " && ".join(
        f"object.data['{field}'] == oldObject.data['{field}']"
        for field in ("requestId", "targetDigest", "expiresAt"))
    policy = {"apiVersion": "admissionregistration.k8s.io/v1",
              "kind": "ValidatingAdmissionPolicy", "metadata": {"name": LIVE_POLICY},
              "spec": {"failurePolicy": "Fail",
                       "matchConstraints": {"resourceRules": [{
                           "apiGroups": [""], "apiVersions": ["v1"],
                           "operations": ["UPDATE"], "resources": ["configmaps"]}]},
                       "matchConditions": [{"name": "owned-expiry-record",
                           "expression": f"request.namespace == '{NS}' && "
                                         f"(request.name == '{LIVE_RECORD}' || request.name == '{READINESS_RECORD}')"}],
                       "validations": [{"expression": f"size(object.data) == 5 && {immutable} "
                                                     f"&& ({' || '.join(choices)})",
                                        "message": "only the designated reviewer can approve its own field on this exact record",
                                        "reason": "Forbidden"}]}}
    apply(lab, policy)
    apply(lab, {"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": LIVE_BINDING},
                "spec": {"policyName": LIVE_POLICY, "validationActions": ["Deny"]}})


def create_observer(lab, case_dir):
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "saf-0602-007-live-expiry-reviewer", "namespace": NS},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [LIVE_RECORD, READINESS_RECORD],
                           "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "saf-0602-007-live-expiry-reviewer", "namespace": NS},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "saf-0602-007-live-expiry-reviewer"},
                "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": actor}
                             for actor in REVIEWERS]})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": LIVE_SA},
                "automountServiceAccountToken": True})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": LIVE_ROLE, "namespace": NS},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [LIVE_RECORD], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": LIVE_ROLE, "namespace": NS},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": LIVE_ROLE},
                "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": LIVE_SA}]})
    source = (case_dir / "live_expiry_job.py").read_text(encoding="utf-8")
    consumer = (case_dir / "expiry_consumer.py").read_text(encoding="utf-8")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": LIVE_CODE},
                "immutable": True, "data": {"live_expiry_job.py": source,
                                              "expiry_consumer.py": consumer}})
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": LIVE_JOB},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                    "template": {"metadata": {"labels": {"saf-k8s.example/fixture": "0602-007-live-expiry"}},
                                 "spec": {"restartPolicy": "Never", "serviceAccountName": LIVE_SA,
                                          "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "containers": [{"name": "expiry-observer", "image": LIVE_IMAGE,
                                                           "command": ["python", "/fixture/live_expiry_job.py"],
                                                           "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                                         "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                           "volumeMounts": [{"name": "source", "mountPath": "/fixture",
                                                                             "readOnly": True}],
                                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                                               "readOnlyRootFilesystem": True,
                                                                               "capabilities": {"drop": ["ALL"]}}}],
                                          "volumes": [{"name": "source", "configMap": {"name": LIVE_CODE}}]}}}}
    lab.create(job)
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        pods = json.loads(lab.kubectl("-n", NS, "get", "pods", "-l", f"job-name={LIVE_JOB}", "-o", "json").stdout)["items"]
        if any(pod.get("status", {}).get("phase") == "Running" for pod in pods):
            return
        if any(pod.get("status", {}).get("phase") == "Failed" for pod in pods):
            lab.block("The case-owned live-expiry Job failed before observing the record")
        time.sleep(0.25)
    lab.block("The case-owned live-expiry Job did not reach Running within the bounded startup window")


def run(lab, case_dir):
    original_before = get_configmap(lab, "saf-0602-007-review")
    original_data = original_before.get("data", {})
    original_uid = original_before.get("metadata", {}).get("uid")
    original_hash = canonical_hash(original_data)

    # This readiness record lets the exact VAP prove it is active before the
    # short real-time record is created, preserving most of its expiry window.
    readiness = base_data("2032-01-01T00:15:00Z")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": READINESS_RECORD, "namespace": NS}, "data": readiness})
    create_observer(lab, case_dir)
    install_guard(lab)
    policy_ready = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        attempt = patch(lab, "saf-security", READINESS_RECORD, {"operations": "approved"}, dry=True)
        if policy_denied(attempt):
            policy_ready = True
            break
        time.sleep(0.25)
    if not policy_ready:
        lab.block("The live-expiry admission guard did not return its expected readiness refusal")

    # Start the consumer before creating the short-lived record. Its clock is
    # observed inside the Pod while the harness and API server provide bounds.
    # (The Job has already started waiting for this exact named record.)
    # create_observer started it above.
    host_before_create = datetime.now(timezone.utc)
    expires_at = stamp(host_before_create + timedelta(seconds=WINDOW_SECONDS))
    created = lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": LIVE_RECORD, "namespace": NS},
                          "data": base_data(expires_at)})
    host_after_create = datetime.now(timezone.utc)
    api_created_text = created.get("metadata", {}).get("creationTimestamp")

    expiry_mutation = (datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                       + timedelta(minutes=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    expiry_change_denied = policy_denied(patch(
        lab, "saf-security", LIVE_RECORD,
        {"security": "approved", "expiresAt": expiry_mutation}, dry=True))
    security_vote = patch(lab, "saf-security", LIVE_RECORD, {"security": "approved"})
    operations_vote = patch(lab, "saf-operations", LIVE_RECORD, {"operations": "approved"})
    approved = get_configmap(lab, LIVE_RECORD)
    approved_data = approved.get("data", {})
    approved_uid = approved.get("metadata", {}).get("uid")
    expected_approved = {**base_data(expires_at), "security": "approved", "operations": "approved"}
    approvals_persisted = (security_vote.returncode == 0 and operations_vote.returncode == 0
                           and approved_data == expected_approved
                           and approved_uid == created.get("metadata", {}).get("uid"))

    job_wait = lab.kubectl("-n", NS, "wait", "--for=condition=complete", f"job/{LIVE_JOB}",
                           "--timeout=80s", timeout=90, allow_failure=True)
    job_status = json.loads(lab.kubectl("-n", NS, "get", "job", LIVE_JOB, "-o", "json").stdout)
    logs = lab.kubectl("-n", NS, "logs", f"job/{LIVE_JOB}", allow_failure=True)
    try:
        job_observation = json.loads(logs.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError, TypeError):
        job_observation = {}
    host_after_job = datetime.now(timezone.utc)

    final_live = get_configmap(lab, LIVE_RECORD)
    final_original = get_configmap(lab, "saf-0602-007-review")
    live_unchanged = (final_live.get("metadata", {}).get("uid") == approved_uid
                      and final_live.get("metadata", {}).get("creationTimestamp") == api_created_text
                      and final_live.get("data", {}) == approved_data)
    original_unchanged = (final_original.get("metadata", {}).get("uid") == original_uid
                          and canonical_hash(final_original.get("data", {})) == original_hash
                          and final_original.get("data", {}) == original_data)
    complete = any(condition.get("type") == "Complete" and condition.get("status") == "True"
                   for condition in job_status.get("status", {}).get("conditions", []))
    succeeded = job_status.get("status", {}).get("succeeded") == 1
    try:
        api_created = instant(api_created_text)
        expiry_instant = instant(expires_at)
        before_instant = instant(job_observation["before_utc"])
        after_instant = instant(job_observation["after_utc"])
        host_before_instant = host_before_create.astimezone(timezone.utc)
        host_after_create_instant = host_after_create.astimezone(timezone.utc)
        host_after_job_instant = host_after_job.astimezone(timezone.utc)
        server_creation_bounded = (
            host_before_instant - timedelta(seconds=HOST_API_CLOCK_TOLERANCE_SECONDS)
            <= api_created <= host_after_create_instant + timedelta(seconds=HOST_API_CLOCK_TOLERANCE_SECONDS))
        job_times_ordered = (api_created <= before_instant < expiry_instant <= after_instant
                             and before_instant <= host_after_job_instant + timedelta(seconds=JOB_HOST_CLOCK_TOLERANCE_SECONDS)
                             and after_instant <= host_after_job_instant + timedelta(seconds=JOB_HOST_CLOCK_TOLERANCE_SECONDS)
                             and host_after_job_instant - after_instant <= timedelta(seconds=JOB_HOST_CLOCK_TOLERANCE_SECONDS))
    except (KeyError, TypeError, ValueError):
        api_created = before_instant = after_instant = expiry_instant = None
        server_creation_bounded = False
        job_times_ordered = False
    clock_bounded = server_creation_bounded and job_times_ordered

    before_allowed = job_observation.get("before_decision") == {
        "permitted": True, "reason": "approved-unexpired"}
    after_denied = job_observation.get("after_decision") == {
        "permitted": False, "reason": "expired"}
    job_record_unchanged = job_observation.get("record_unchanged") is True
    job_used_exact_record = (
        job_observation.get("record_uid") == approved_uid
        and job_observation.get("record_created_at") == api_created_text
        and job_observation.get("expires_at") == expires_at
        and job_observation.get("record_sha256") == canonical_hash(approved_data))
    passed = (policy_ready and approvals_persisted and expiry_change_denied and complete and succeeded
              and job_wait.returncode == 0 and job_observation.get("status") == "passed"
              and before_allowed and after_denied and job_record_unchanged and job_used_exact_record
              and live_unchanged
              and original_unchanged and clock_bounded)

    raw = {"scope": "Second owned inert ConfigMap; a non-root Job reads only that named object without exposing its projected token, evaluates the existing reference consumer with its live UTC clock, and waits boundedly for expiry. No image exemption or workload authorization is linked.",
           "live_record": {"name": LIVE_RECORD, "uid": approved_uid, "data": approved_data,
                           "unchanged_after_job": live_unchanged},
           "original_approval_record": {"uid": original_uid, "data_sha256_before": original_hash,
                                        "unchanged_after_job": original_unchanged},
           "approvals": {"security_patch_succeeded": security_vote.returncode == 0,
                         "operations_patch_succeeded": operations_vote.returncode == 0,
                         "exact_approvals_persisted": approvals_persisted,
                         "expiry_mutation_denied": expiry_change_denied},
           "time_observations": {"harness_before_record_create_utc": stamp(host_before_create),
                                 "api_server_creation_timestamp": api_created_text,
                                 "harness_after_record_create_utc": stamp(host_after_create),
                                 "consumer_before_utc": job_observation.get("before_utc"),
                                 "expires_at_utc": expires_at,
                                 "consumer_after_utc": job_observation.get("after_utc"),
                                 "harness_after_job_utc": stamp(host_after_job),
                                 "api_creation_within_harness_bracket": server_creation_bounded,
                                 "job_observation_within_live_time_bound": job_times_ordered,
                                 "trusted_external_time_source_claimed": False,
                                 "kind_and_host_clock_lineage_independent": False},
           "consumer": job_observation,
           "job_used_exact_approved_record": job_used_exact_record,
           "job": {"complete": complete, "succeeded": succeeded,
                   "wait_returncode_zero": job_wait.returncode == 0},
           "provider_identity_or_image_admission_claimed": False}
    (lab.evidence / "live-expiry-observations.raw.json").write_text(
        json.dumps(raw, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("positive", "An approved inert record allows before its live UTC expiry and denies after without record mutation",
              passed,
              {"separate_approvals_persisted": approvals_persisted,
               "expiry_field_mutation_denied": expiry_change_denied,
               "same_record_allowed_before_expiry": before_allowed,
               "same_record_denied_after_expiry": after_denied,
               "job_used_exact_approved_record": job_used_exact_record,
               "approved_record_unchanged_during_live_expiry": live_unchanged and job_record_unchanged,
               "initial_approval_record_unchanged": original_unchanged,
               "live_utc_bounded_by_harness_and_api_server_observations": clock_bounded,
               "trusted_external_clock_claimed": False,
               "raw_evidence": "live-expiry-observations.raw.json"})
