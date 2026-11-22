"""Check a two-person gate on synthetic audit annotation and deletion operations."""
import json
from pathlib import Path
import time

NS = "saf-test"
TARGET = "synthetic-audit-log-record"
DECOY = "synthetic-audit-log-decoy"
LEDGER = "saf-audit-approval-ledger"
PURGE_LEDGER = "saf-audit-purge-ledger"
PURGE = "synthetic-audit-purge-record"
REVIEWERS = ("security-reviewer", "records-reviewer")
EXECUTOR = "audit-workflow-executor"
ACTORS = (*REVIEWERS, EXECUTOR)
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "A disposable Kubernetes v1.36.1 API server protects a synthetic audit-record annotation "
    "update and a separate synthetic purge. Three non-admin ServiceAccounts use scoped RBAC "
    "and native ValidatingAdmissionPolicies. Each approval ledger binds the exact UID and "
    "operation to separate eligible reviewer fields. Human identity, storage backend workflows, "
    "approval expiry, and production governance require separate evidence."
)


def obj(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def grant(lab, name, actors, rules):
    lab.create(obj(RBAC, "Role", name, rules=rules))
    lab.create(obj(RBAC, "RoleBinding", name,
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                   subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}
                             for actor in actors]))


def record(lab, name, event):
    return lab.create(obj("v1", "ConfigMap", name, data={
        "recordId": name, "event": event, "annotation": "unreviewed",
    }))


def user(actor):
    return f"system:serviceaccount:{NS}:{actor}"


def install_policy(lab, name, resource, operations, expression, message, *, params=None, names=None):
    names = names or [TARGET, DECOY]
    spec = {
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                  "operations": operations, "resources": [resource]}]},
        "matchConditions": [{"name": "owned-objects-only",
                             "expression": f"request.namespace == '{NS}' && request.name in {json.dumps(names)}"}],
        "validations": [{"expression": expression, "message": message, "reason": "Forbidden"}],
    }
    binding = {"policyName": name, "validationActions": ["Deny"]}
    if params:
        spec["paramKind"] = {"apiVersion": "v1", "kind": "ConfigMap"}
        binding["paramRef"] = {"name": params, "namespace": NS, "parameterNotFoundAction": "Deny"}
    lab.create(obj(ADMISSION, "ValidatingAdmissionPolicy", name, spec=spec))
    lab.create(obj(ADMISSION, "ValidatingAdmissionPolicyBinding", name, spec=binding))


def probe(lab, actor, action, uid=None):
    argv = [action, uid] if uid else [action]
    result = json.loads(lab.kubectl("exec", actor, "--", "python", "/fixture/probe.py", *argv).stdout)
    with (lab.evidence / "probe-observations.jsonl").open("a") as evidence:
        evidence.write(json.dumps({"actor": actor, "action": action, "target_uid": uid, "response": result}) + "\n")
    return result


def denied(result, policy=None, detail=None):
    return (result.get("code") == 403 and result.get("reason") == "Forbidden"
            and (policy is None or policy in result.get("detail", ""))
            and (detail is None or detail in result.get("detail", "")))


def wait_denial(lab, actor, action, policy, detail, seconds=25, uid=None):
    end = time.monotonic() + seconds
    while True:
        result = probe(lab, actor, action, uid)
        if denied(result, policy, detail) or time.monotonic() >= end:
            return result
        time.sleep(0.5)


def wait_allowed(lab, actor, action, uid=None):
    deadline = time.monotonic() + 25
    while True:
        response = probe(lab, actor, action, uid)
        if response["code"] == 200 or time.monotonic() >= deadline:
            return response
        time.sleep(.5)


def run(lab):
    target = record(lab, TARGET, "synthetic event: fixture login succeeded")
    decoy = record(lab, DECOY, "synthetic event: fixture logout succeeded")
    purge = record(lab, PURGE, "synthetic event: purge fixture")
    purge_uid = purge["metadata"]["uid"]
    uid = target["metadata"]["uid"]
    decoy_uid = decoy["metadata"]["uid"]
    if uid == decoy_uid:
        lab.block("API returned duplicate UIDs for distinct fixture records")
    lab.create(obj("v1", "ConfigMap", LEDGER, data={
        "targetUid": uid, "action": "modify-annotation", "approvedValue": "reviewed",
        "security": "pending", "records": "pending",
    }))
    lab.create(obj("v1", "ConfigMap", PURGE_LEDGER, data={
        "targetUid": purge_uid, "action": "purge-record", "approvedValue": "deleted",
        "security": "pending", "records": "pending",
    }))
    script = Path(__file__).with_name("probe.py").read_text()
    lab.create(obj("v1", "ConfigMap", "saf-audit-probe", data={"probe.py": script}))
    for actor in ACTORS:
        lab.create(obj("v1", "ServiceAccount", actor))
    grant(lab, "saf-audit-vote", REVIEWERS, [{"apiGroups": [""], "resources": ["configmaps"],
                                                "resourceNames": [LEDGER, PURGE_LEDGER], "verbs": ["get", "patch"]}])
    grant(lab, "saf-audit-execute", [EXECUTOR], [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET, DECOY],
         "verbs": ["get", "patch"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [PURGE, DECOY],
         "verbs": ["get", "delete"]},
    ])
    for actor in ACTORS:
        lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": actor}, "spec": {
            "restartPolicy": "Never", "serviceAccountName": actor,
            "automountServiceAccountToken": True,
            "containers": [{"name": "probe", "image": IMAGE,
                            "command": ["python", "-c", "import time; time.sleep(3600)"],
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                "allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "seccompProfile": {"type": "RuntimeDefault"}},
                            "volumeMounts": [{"name": "probe", "mountPath": "/fixture", "readOnly": True}]}],
            "volumes": [{"name": "probe", "configMap": {"name": "saf-audit-probe"}}],
        }})
    for actor in ACTORS:
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{actor}", "--timeout=90s", timeout=100)

    baseline = probe(lab, EXECUTOR, "dry-target-update")
    lab.check("red", "Before enforcement, the scoped ordinary executor can submit the exact synthetic update",
              baseline["code"] == 200, {"http_status": baseline["code"],
                                         "annotation_change": "unreviewed -> reviewed", "dry_run": True})

    baseline_purge = probe(lab, EXECUTOR, "dry-purge", purge_uid)
    pre_gate = json.loads(lab.kubectl("get", "configmap", PURGE, "-o", "json").stdout)
    lab.check("red", "Before enforcement, a dry-run DELETE succeeds and the exact object stays present",
              baseline_purge["code"] == 200 and pre_gate["metadata"]["uid"] == purge_uid,
              {"http_status": baseline_purge["code"], "same_record_after_dry_run": True})

    vote_policy, action_policy = "saf-audit-vote-gate", "saf-audit-action-gate"
    vote_message, action_message = "reviewer may approve only its assigned field", "two bound approvals required for this exact audit annotation update"
    vote_expr = (
        f"object.data['targetUid'] == oldObject.data['targetUid'] && object.data['action'] == oldObject.data['action'] && "
        f"object.data['approvedValue'] == oldObject.data['approvedValue'] && size(object.data) == 5 && "
        f"((request.userInfo.username == '{user(REVIEWERS[0])}' && object.data['security'] == 'approved' && "
        "object.data['records'] == oldObject.data['records']) || "
        f"(request.userInfo.username == '{user(REVIEWERS[1])}' && object.data['records'] == 'approved' && "
        "object.data['security'] == oldObject.data['security']))"
    )
    install_policy(lab, vote_policy, "configmaps", ["UPDATE"], vote_expr, vote_message,
                   names=[LEDGER, PURGE_LEDGER])
    action_expr = (
        f"request.userInfo.username == '{user(EXECUTOR)}' && params != null && "
        "params.data['targetUid'] == oldObject.metadata.uid && params.data['action'] == 'modify-annotation' && "
        "params.data['approvedValue'] == 'reviewed' && params.data['security'] == 'approved' && "
        "params.data['records'] == 'approved' && size(params.data) == 5 && "
        "object.metadata.uid == oldObject.metadata.uid && object.data['recordId'] == oldObject.data['recordId'] && "
        "object.data['event'] == oldObject.data['event'] && size(object.data) == 3 && "
        "object.data['annotation'] == params.data['approvedValue'] && oldObject.data['annotation'] == 'unreviewed'"
    )
    install_policy(lab, action_policy, "configmaps", ["UPDATE"], action_expr, action_message, params=LEDGER)

    zero = wait_denial(lab, EXECUTOR, "dry-target-update", action_policy, action_message)
    lab.check("green", "The exact update is denied with zero approvals",
              denied(zero, action_policy, action_message), {"http_status": zero["code"], "policy_denied": True})

    one_vote = probe(lab, REVIEWERS[0], "security-vote")
    repeat_vote = probe(lab, REVIEWERS[0], "security-vote")
    one = wait_denial(lab, EXECUTOR, "dry-target-update", action_policy, action_message)
    lab.check("green", "One vote and an idempotent repeat by that same actor still leave one approval",
              one_vote["code"] == repeat_vote["code"] == 200 and denied(one, action_policy, action_message),
              {"first_vote_http": one_vote["code"], "repeat_http": repeat_vote["code"],
               "executor_http": one["code"], "distinct_approvals": 1})

    same_actor = probe(lab, REVIEWERS[0], "records-vote")
    lab.check("green", "The security reviewer cannot fill the records reviewer approval field",
              denied(same_actor, vote_policy, vote_message),
              {"http_status": same_actor["code"], "policy_denied": True})

    direct = probe(lab, REVIEWERS[0], "direct-target-update")
    lab.check("green", "A reviewer without record-update RBAC cannot directly alter the audit record",
              denied(direct), {"http_status": direct["code"], "reason": direct["reason"],
                               "detail": direct["detail"][:240]})

    second_vote = probe(lab, REVIEWERS[1], "records-vote")
    cross = wait_denial(lab, EXECUTOR, "dry-decoy-update", action_policy, action_message)
    lab.check("green", "Approvals bound to the target UID do not authorize the distinct decoy record UID",
              second_vote["code"] == 200 and denied(cross, action_policy, action_message),
              {"second_vote_http": second_vote["code"], "distinct_target_and_decoy": uid != decoy_uid,
               "cross_record_http": cross["code"], "policy_denied": True})

    out_of_scope = probe(lab, EXECUTOR, "dry-event-update")
    lab.check("green", "The approved annotation action cannot modify retained event content",
              denied(out_of_scope, action_policy, action_message),
              {"http_status": out_of_scope["code"], "policy_denied": True})

    stored = json.loads(lab.kubectl("get", "configmap", LEDGER, "-o", "json").stdout)["data"]
    approved = wait_allowed(lab, EXECUTOR, "dry-target-update")
    lab.check("positive", "Two distinct approvals allow the normal exact-UID annotation update",
              stored == {"targetUid": uid, "action": "modify-annotation", "approvedValue": "reviewed",
                         "security": "approved", "records": "approved"} and approved["code"] == 200,
              {"ledger_target_uid_matches": stored.get("targetUid") == uid,
               "approval_identities": [user(REVIEWERS[0]), user(REVIEWERS[1])],
               "approved_action": stored.get("action"), "dry_run_http": approved["code"]})
    actual = probe(lab, EXECUTOR, "target-update")
    updated = json.loads(lab.kubectl("get", "configmap", TARGET, "-o", "json").stdout)
    lab.check("positive", "The approved workflow performs only the permitted synthetic annotation update",
              actual["code"] == 200 and updated["metadata"]["uid"] == uid
              and updated["data"] == {"recordId": TARGET,
                                       "event": "synthetic event: fixture login succeeded",
                                       "annotation": "reviewed"},
              {"http_status": actual["code"], "uid_unchanged": updated["metadata"]["uid"] == uid,
               "event_unchanged": updated["data"].get("event") == "synthetic event: fixture login succeeded",
               "annotation": updated["data"].get("annotation")})

    purge_policy = "saf-audit-purge-policy"
    purge_message = "two bound approvals required to purge this exact synthetic audit record"
    install_policy(
        lab, purge_policy, "configmaps", ["DELETE"],
        f"request.userInfo.username == '{user(EXECUTOR)}' && oldObject != null && params != null && "
        "params.data.targetUid == oldObject.metadata.uid && params.data.action == 'purge-record' && "
        "params.data.approvedValue == 'deleted' && params.data.security == 'approved' && "
        "params.data.records == 'approved' && size(params.data) == 5",
        purge_message, params=PURGE_LEDGER, names=[PURGE, DECOY],
    )
    never_approved = wait_denial(lab, EXECUTOR, "dry-purge", purge_policy, purge_message, uid=purge_uid)
    reviewer = probe(lab, REVIEWERS[0], "dry-purge", purge_uid)
    lab.check("green", "Unapproved purge and direct reviewer deletion are independently denied",
              denied(never_approved, purge_policy, purge_message) and denied(reviewer)
              and "cannot delete resource" in reviewer["detail"],
              {"executor_http": never_approved["code"], "reviewer_http": reviewer["code"]})

    vote = probe(lab, REVIEWERS[0], "purge-security-vote")
    repeat = probe(lab, REVIEWERS[0], "purge-security-vote")
    other_field = probe(lab, REVIEWERS[0], "purge-records-vote")
    only_one = wait_denial(lab, EXECUTOR, "dry-purge", purge_policy, purge_message, uid=purge_uid)
    lab.check("green", "One reviewer still cannot approve the other field or authorize deletion",
              vote["code"] == repeat["code"] == 200 and denied(other_field, vote_policy, vote_message)
              and denied(only_one, purge_policy, purge_message),
              {"votes_from_one_identity": 1, "second_field_http": other_field["code"],
               "purge_http": only_one["code"]})

    distinct_vote = probe(lab, REVIEWERS[1], "purge-records-vote")
    crossed = wait_denial(lab, EXECUTOR, "dry-purge-decoy", purge_policy, purge_message, uid=decoy_uid)
    approved = wait_allowed(lab, EXECUTOR, "dry-purge", uid=purge_uid)
    final_ballot = json.loads(lab.kubectl("get", "configmap", PURGE_LEDGER, "-o", "json").stdout)["data"]
    lab.check("positive", "Two approvals permit only the exact synthetic purge and leave the decoy in place",
              distinct_vote["code"] == 200 and approved["code"] == 200
              and final_ballot == {"targetUid": purge_uid, "action": "purge-record", "approvedValue": "deleted",
                                   "security": "approved", "records": "approved"}
              and denied(crossed, purge_policy, purge_message),
              {"second_reviewer_http": distinct_vote["code"], "approved_purge_http": approved["code"],
               "decoy_purge_http": crossed["code"]})

    deleted = probe(lab, EXECUTOR, "purge", purge_uid)
    missing = lab.kubectl("get", "configmap", PURGE, "--ignore-not-found", "-o", "name").stdout
    decoy_after = json.loads(lab.kubectl("get", "configmap", DECOY, "-o", "json").stdout)
    lab.check("positive", "The approved DELETE removes the exact target without removing the other record",
              deleted["code"] == 200 and not missing and decoy_after["metadata"]["uid"] == decoy_uid,
              {"http_status": deleted["code"], "requested_record_absent": not missing, "decoy_preserved": True})

    purge_review = json.loads(lab.kubectl("get", "configmap", PURGE_LEDGER, "-o", "json").stdout)
    state = {
        "applicable_uids": {"update": uid, "purge": purge_uid, "decoy": decoy_uid},
        "approved_update": stored, "approved_purge": purge_review["data"],
        "updated_record": updated["data"], "purge_object_absent": not missing,
        "decoy_uid_after": decoy_after["metadata"]["uid"],
    }
    (lab.evidence / "approved-record-state.json").write_text(json.dumps(state, indent=2) + "\n")
