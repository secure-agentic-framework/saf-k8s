"""Enforce exact-target dual approval for deletion of one synthetic PV record."""
import json
from pathlib import Path
import time

from fixtures import pod, ready

NS = "saf-test"
TARGET = "synthetic-retained-archive"
APPROVAL = "saf-approval-ledger"
ACTORS = ("security-reviewer", "data-reviewer", "fixture-executor")
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "A disposable Kubernetes v1.36.1 API server protects one synthetic, unbound Retain PV object. "
    "Separate real fixture ServiceAccounts record independent approvals on an exact-UID ledger. "
    "Native admission blocks the fixture executor's normal DELETE until both approvals exist. "
    "Actual backend destruction, sanitization, approval expiry, governance, and production "
    "integration require separate evidence."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def grant(lab, name, actors, rules, *, cluster=False):
    role = "ClusterRole" if cluster else "Role"
    lab.create(object_spec(RBAC, role, name, rules=rules))
    lab.create(object_spec(RBAC, role + "Binding", name,
                            roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": role, "name": name},
                            subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}
                                      for actor in actors]))


def storage_record(lab):
    return lab.create(object_spec("v1", "PersistentVolume", TARGET, spec={
        "persistentVolumeReclaimPolicy": "Retain",
        "capacity": {"storage": "1Mi"}, "accessModes": ["ReadWriteOnce"],
        "storageClassName": "saf-unbound-fixture",
        "local": {"path": "/var/local-path-provisioner/unmounted-approval-demo"},
        "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [{
            "key": "kubernetes.io/hostname", "operator": "In", "values": [f"{lab.cluster}-control-plane"],
        }]}]}},
    }))


def install_policy(lab, name, resource, group, op, expression, message, match, *, params=False):
    spec = {
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{
            "apiGroups": [group], "apiVersions": ["v1"], "operations": [op], "resources": [resource],
        }]},
        "matchConditions": [{"name": "exact-fixture", "expression": match}],
        "validations": [{"expression": expression, "message": message, "reason": "Forbidden"}],
    }
    binding = {"policyName": name, "validationActions": ["Deny"]}
    if params:
        spec["paramKind"] = {"apiVersion": "v1", "kind": "ConfigMap"}
        binding["paramRef"] = {"name": APPROVAL, "namespace": NS, "parameterNotFoundAction": "Deny"}
    lab.create(object_spec(ADMISSION, "ValidatingAdmissionPolicy", name, spec=spec))
    lab.create(object_spec(ADMISSION, "ValidatingAdmissionPolicyBinding", name, spec=binding))


def user(actor):
    return f"system:serviceaccount:{NS}:{actor}"


def probe(lab, actor, action):
    result = lab.kubectl("exec", actor, "--", "python", "/fixture/probe.py", action)
    return json.loads(result.stdout)


def rejected(result, policy, detail):
    return (result["code"] == 403 and result["reason"] == "Forbidden"
            and policy in result["detail"] and detail in result["detail"])


def run(lab):
    pv = storage_record(lab)
    target_uid = pv["metadata"]["uid"]
    lab.create(object_spec("v1", "ConfigMap", APPROVAL,
                          data={"volumeUid": target_uid, "security": "pending", "dataOwner": "pending"}))
    script = Path(__file__).with_name("probe.py").read_text()
    lab.create(object_spec("v1", "ConfigMap", "saf-dual-probe", data={"probe.py": script}))
    for actor in ACTORS:
        lab.create(object_spec("v1", "ServiceAccount", actor))
    grant(lab, "saf-dual-vote", ACTORS[:2], [{"apiGroups": [""], "resources": ["configmaps"],
                                          "resourceNames": [APPROVAL], "verbs": ["get", "patch"]}])
    grant(lab, "saf-dual-executor", ACTORS[2:], [{"apiGroups": [""], "resources": ["persistentvolumes"],
                                               "resourceNames": [TARGET], "verbs": ["get", "delete"]}], cluster=True)
    grant(lab, "saf-dual-read", ACTORS[2:], [{"apiGroups": [""], "resources": ["configmaps"],
                                           "resourceNames": [APPROVAL], "verbs": ["get"]}])
    for actor in ACTORS:
        lab.create(pod(actor, [{
            "name": "reviewer", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(3600)"],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
            "volumeMounts": [{"name": "probe", "mountPath": "/fixture", "readOnly": True}],
        }], serviceAccountName=actor, automountServiceAccountToken=True,
            volumes=[{"name": "probe", "configMap": {"name": "saf-dual-probe"}}]))
    for actor in ACTORS:
        ready(lab, actor)

    baseline = probe(lab, ACTORS[2], "dry-delete")
    lab.check("red", "The authorized executor's dry-run DELETE reaches the API before dual approval is enforced",
              baseline["code"] == 200, {"http_status": baseline["code"]})

    vote = "saf-0701-006-vote"
    delete = "saf-0701-006-delete"
    vote_error = "each reviewer may approve only its own field"
    delete_error = "two independent approvals are required for this retained volume"
    install_policy(lab, vote, "configmaps", "", "UPDATE",
                   f"object.data['volumeUid'] == oldObject.data['volumeUid'] && size(object.data) == 3 && "
                   f"((request.userInfo.username == '{user(ACTORS[0])}' && object.data['security'] == 'approved' "
                   "&& object.data['dataOwner'] == oldObject.data['dataOwner']) || "
                   f"(request.userInfo.username == '{user(ACTORS[1])}' && object.data['dataOwner'] == 'approved' "
                   "&& object.data['security'] == oldObject.data['security']))", vote_error,
                   f"request.namespace == '{NS}' && request.name == '{APPROVAL}'")
    install_policy(lab, delete, "persistentvolumes", "", "DELETE",
                   f"request.userInfo.username == '{user(ACTORS[2])}' && params != null "
                   "&& params.data['volumeUid'] == oldObject.metadata.uid "
                   "&& params.data['security'] == 'approved' && params.data['dataOwner'] == 'approved'",
                   delete_error, f"request.name == '{TARGET}'", params=True)

    deadline = time.monotonic() + 25
    while True:
        denied = probe(lab, ACTORS[2], "dry-delete")
        if rejected(denied, delete, delete_error) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "Deletion is refused with zero approvals",
              rejected(denied, delete, delete_error), {"http_status": denied["code"], "policy_denied": True})

    deadline = time.monotonic() + 20
    while True:
        wrong = probe(lab, ACTORS[0], "check-other-vote")
        if rejected(wrong, vote, vote_error) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The security identity may not record the data owner's vote",
              rejected(wrong, vote, vote_error), {"http_status": wrong["code"], "policy_denied": True})
    first = probe(lab, ACTORS[0], "security-vote")
    repeat = probe(lab, ACTORS[0], "security-vote")
    only_one = probe(lab, ACTORS[2], "dry-delete")
    lab.check("green", "Reapplying the same review cannot satisfy the second approval",
              first["code"] == repeat["code"] == 200 and rejected(only_one, delete, delete_error),
              {"first_approved": first["code"] == 200, "duplicate_approved_idempotently": repeat["code"] == 200,
               "executor_http_status": only_one["code"]})
    second = probe(lab, ACTORS[1], "data-vote")
    ledger = json.loads(lab.kubectl("get", "configmap", APPROVAL, "-o", "json").stdout)["data"]
    deadline = time.monotonic() + 20
    while True:
        authorized = probe(lab, ACTORS[2], "dry-delete")
        if authorized["code"] == 200 or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    if authorized["code"] != 200:
        lab.block("The approval ledger did not converge in the deletion policy")
    result = probe(lab, ACTORS[2], "delete")
    deadline = time.monotonic() + 15
    while True:
        surviving = lab.kubectl("get", "pv", TARGET, "--ignore-not-found", "-o", "name").stdout.strip()
        if not surviving or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("positive", "The approved synthetic PV record can be deleted for the exact ledger UID",
              second["code"] == 200 and ledger == {"volumeUid": target_uid, "security": "approved", "dataOwner": "approved"}
              and result["code"] == 200 and not surviving,
              {"approved_ledger_matches_uid": ledger.get("volumeUid") == target_uid,
               "second_vote_accepted": second["code"] == 200, "executor_http_status": result["code"],
               "pv_record_removed": not surviving})
