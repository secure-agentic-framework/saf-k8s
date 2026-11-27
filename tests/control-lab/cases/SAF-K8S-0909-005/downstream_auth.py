"""Exercise one fixed native Kubernetes downstream action under scoped pod identities."""
from __future__ import annotations

import json
import time

NS = "saf-test"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
CODE = "fixture-downstream-auth-code"
APPROVED = "fixture-downstream-approved"
ALTERNATE = "fixture-downstream-alternate"
ACTION_SA = "fixture-downstream-action"
CONSUMER_SA = "fixture-downstream-consumer"
ACTION_ROLE = "fixture-downstream-action"
CONSUMER_ROLE = "fixture-downstream-consumer"
CONSUMER_POD = "fixture-downstream-consumer"
ACTION_POD = "fixture-downstream-action"
RESOURCE = "configmaps"
API_BASE = f"https://kubernetes.default.svc/api/v1/namespaces/{NS}/{RESOURCE}"
PENDING = "pending-v1"
PROCESSED = "processed-v1"

CLIENT = r'''import json, ssl, sys
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

actor, name, uid, rv, alternate, alternate_uid, alternate_rv = sys.argv[1:]
root = "/var/run/secrets/kubernetes.io/serviceaccount"
token = open(root + "/token", encoding="utf-8").read().strip()
context = ssl.create_default_context(cafile=root + "/ca.crt")
opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
base = "https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/"

def send(method, target, body=None, content_type=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = content_type
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = Request(base + target, data=data, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=8)
    except HTTPError as error:
        error.read(4096)
        return error.code, None
    with response:
        raw = response.read(65536)
        return response.status, json.loads(raw) if raw else None

def patch(uid_value, rv_value):
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid_value},
        {"op": "test", "path": "/metadata/resourceVersion", "value": rv_value},
        {"op": "replace", "path": "/data/status", "value": "processed-v1"},
    ]

read_status, record = send("GET", name)
exact_read = (read_status == 200 and record is not None
              and record.get("metadata", {}).get("uid") == uid
              and record.get("metadata", {}).get("resourceVersion") == rv
              and record.get("data", {}).get("status") == "pending-v1")
if not exact_read:
    raise RuntimeError("owned downstream record did not match its fixed input")

if actor == "consumer":
    target_status, _ = send("PATCH", name, patch(uid, rv), "application/json-patch+json")
    out = {"actor": "consumer", "tls_peer_verified": True,
           "exact_record_read_permitted": True, "identical_action_status": target_status}
elif actor == "action":
    target_status, updated = send("PATCH", name, patch(uid, rv), "application/json-patch+json")
    alternate_status, _ = send("PATCH", alternate,
                               patch(alternate_uid, alternate_rv),
                               "application/json-patch+json")
    out = {"actor": "action", "tls_peer_verified": True,
           "exact_record_read_permitted": True, "approved_action_status": target_status,
           "alternate_action_status": alternate_status,
           "approved_update_returned_exact_uid": bool(updated and
               updated.get("metadata", {}).get("uid") == uid and
               updated.get("data", {}).get("status") == "processed-v1")}
else:
    raise ValueError("fixture actor is not allowlisted")
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
'''


def create(lab, kind, name, *, api="v1", **fields):
    lab.create({"apiVersion": api, "kind": kind,
                "metadata": {"name": name, "namespace": NS}, **fields})


def get_json(lab, kind, name, api="-o", output="json"):
    raw = lab.kubectl("-n", NS, "get", kind, name, api, output).stdout
    return json.loads(raw)


def pod(lab, name, service_account, image, code_config, args):
    request = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NS,
                     "labels": {"saf-k8s.example/0909-005": "downstream-action"}},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": service_account,
            "automountServiceAccountToken": True,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "fixture", "image": image,
                "imagePullPolicy": "Never",
                "command": ["python", "/fixture/downstream_client.py"],
                "args": args,
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True, "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "code", "configMap": {"name": code_config,
                "items": [{"key": "downstream_client.py", "path": "downstream_client.py"}]}}],
        }}
    lab.create(request)


def wait_succeeded(lab, name, timeout=80):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        latest = get_json(lab, "pod", name)
        phase = latest.get("status", {}).get("phase")
        if phase in ("Succeeded", "Failed"):
            return latest
        time.sleep(0.4)
    lab.block("A bounded downstream authorization fixture Pod did not finish")


def record_logs(lab, pod_name):
    result = lab.kubectl("-n", NS, "logs", "pod/" + pod_name, timeout=12)
    rows = result.stdout.splitlines()
    if len(rows) != 1:
        lab.block("A downstream authorization fixture emitted unexpected log framing")
    observed = json.loads(rows[0])
    if set(observed) not in (
        {"actor", "tls_peer_verified", "exact_record_read_permitted", "identical_action_status"},
        {"actor", "tls_peer_verified", "exact_record_read_permitted", "approved_action_status",
         "alternate_action_status", "approved_update_returned_exact_uid"},
    ):
        lab.block("A downstream authorization fixture emitted unexpected evidence fields")
    return observed


def has_projected_api_credential(pod_object):
    spec = pod_object.get("spec", {})
    containers = spec.get("containers", [])
    if len(containers) != 1:
        return False
    mounted_names = {item.get("name") for item in containers[0].get("volumeMounts", [])
                     if item.get("mountPath") == "/var/run/secrets/kubernetes.io/serviceaccount"}
    for volume in spec.get("volumes", []):
        projected = volume.get("projected", {})
        sources = projected.get("sources", [])
        if (volume.get("name") in mounted_names and
                any(isinstance(item.get("serviceAccountToken"), dict) for item in sources)):
            return True
    return False


def run(lab, image):
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"downstream_client.py": CLIENT})
    for name, status in ((APPROVED, PENDING), (ALTERNATE, PENDING)):
        create(lab, "ConfigMap", name, data={"record_id": name, "status": status,
                                             "action": "fixture-consume-v1"})
    create(lab, "ServiceAccount", ACTION_SA, automountServiceAccountToken=True)
    create(lab, "ServiceAccount", CONSUMER_SA, automountServiceAccountToken=True)

    create(lab, "Role", CONSUMER_ROLE, api="rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups": [""], "resources": [RESOURCE],
        "resourceNames": [APPROVED, ALTERNATE], "verbs": ["get"],
    }])
    create(lab, "RoleBinding", CONSUMER_ROLE, api="rbac.authorization.k8s.io/v1",
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": CONSUMER_ROLE},
           subjects=[{"kind": "ServiceAccount", "name": CONSUMER_SA, "namespace": NS}])
    create(lab, "Role", ACTION_ROLE, api="rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups": [""], "resources": [RESOURCE], "resourceNames": [APPROVED],
        "verbs": ["get", "patch"],
    }])
    create(lab, "RoleBinding", ACTION_ROLE, api="rbac.authorization.k8s.io/v1",
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": ACTION_ROLE},
           subjects=[{"kind": "ServiceAccount", "name": ACTION_SA, "namespace": NS}])

    approved_before = get_json(lab, "configmap", APPROVED)
    alternate_before = get_json(lab, "configmap", ALTERNATE)
    approved_uid = approved_before.get("metadata", {}).get("uid")
    approved_rv = approved_before.get("metadata", {}).get("resourceVersion")
    alternate_uid = alternate_before.get("metadata", {}).get("uid")
    alternate_rv = alternate_before.get("metadata", {}).get("resourceVersion")
    if not all((approved_uid, approved_rv, alternate_uid, alternate_rv)):
        lab.block("Owned downstream fixture records lack Kubernetes UID or resourceVersion")

    # The ordinary consumer first reads the exact approved record, then sends
    # the same fixed JSON Patch that the separate action identity will send.
    consumer_args = ["consumer", APPROVED, approved_uid, approved_rv,
                     ALTERNATE, alternate_uid, alternate_rv]
    pod(lab, CONSUMER_POD, CONSUMER_SA, image, CODE, consumer_args)
    consumer_live = wait_succeeded(lab, CONSUMER_POD)
    consumer = record_logs(lab, CONSUMER_POD)

    action_args = ["action", APPROVED, approved_uid, approved_rv,
                   ALTERNATE, alternate_uid, alternate_rv]
    pod(lab, ACTION_POD, ACTION_SA, image, CODE, action_args)
    action_live = wait_succeeded(lab, ACTION_POD)
    action = record_logs(lab, ACTION_POD)

    approved_after = get_json(lab, "configmap", APPROVED)
    alternate_after = get_json(lab, "configmap", ALTERNATE)
    consumer_rule = get_json(lab, "role", CONSUMER_ROLE, "-o", "json")
    action_rule = get_json(lab, "role", ACTION_ROLE, "-o", "json")
    consumer_bind = get_json(lab, "rolebinding", CONSUMER_ROLE, "-o", "json")
    action_bind = get_json(lab, "rolebinding", ACTION_ROLE, "-o", "json")
    approved_pod = get_json(lab, "pod", CONSUMER_POD, "-o", "json")
    action_pod = get_json(lab, "pod", ACTION_POD, "-o", "json")
    consumer_status = consumer_live.get("status", {}).get("containerStatuses", [{}])[0]
    action_status = action_live.get("status", {}).get("containerStatuses", [{}])[0]
    approved_rule = {"apiGroups": [""], "resources": [RESOURCE],
                     "resourceNames": [APPROVED], "verbs": ["get", "patch"]}
    retrieval_rule = {"apiGroups": [""], "resources": [RESOURCE],
                      "resourceNames": [APPROVED, ALTERNATE], "verbs": ["get"]}
    consumer_permissions = consumer_rule.get("rules") == [retrieval_rule]
    action_permissions = action_rule.get("rules") == [approved_rule]
    consumer_subjects = [{key: item.get(key) for key in ("kind", "name", "namespace")}
                         for item in consumer_bind.get("subjects", [])]
    action_subjects = [{key: item.get(key) for key in ("kind", "name", "namespace")}
                       for item in action_bind.get("subjects", [])]
    consumer_subject_scoped = consumer_subjects == [
        {"kind": "ServiceAccount", "name": CONSUMER_SA, "namespace": NS}]
    action_subject_scoped = action_subjects == [
        {"kind": "ServiceAccount", "name": ACTION_SA, "namespace": NS}]
    consumer_role_ref = consumer_bind.get("roleRef") == {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": CONSUMER_ROLE}
    action_role_ref = action_bind.get("roleRef") == {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACTION_ROLE}
    consumer_result = consumer_live.get("status", {}).get("phase") == "Succeeded" and \
        consumer_status.get("state", {}).get("terminated", {}).get("exitCode") == 0
    action_result = action_live.get("status", {}).get("phase") == "Succeeded" and \
        action_status.get("state", {}).get("terminated", {}).get("exitCode") == 0
    consumer_token_projected = has_projected_api_credential(approved_pod)
    action_token_projected = has_projected_api_credential(action_pod)
    checks = {
        "only_action_identity_can_update_the_approved_record": (
            action_result and action.get("actor") == "action"
            and action.get("tls_peer_verified") is True
            and action.get("exact_record_read_permitted") is True
            and action.get("approved_action_status") == 200
            and consumer_result and consumer.get("actor") == "consumer"
            and consumer.get("tls_peer_verified") is True
            and consumer.get("exact_record_read_permitted") is True
            and consumer.get("identical_action_status") == 403
            and approved_pod.get("spec", {}).get("serviceAccountName") == CONSUMER_SA
            and approved_pod.get("spec", {}).get("automountServiceAccountToken") is True
            and consumer_token_projected
            and approved_pod.get("spec", {}).get("restartPolicy") == "Never"
            and approved_pod.get("spec", {}).get("containers", [{}])[0].get("image") == image
            and approved_pod.get("spec", {}).get("containers", [{}])[0].get("args") == consumer_args
            and action_pod.get("spec", {}).get("serviceAccountName") == ACTION_SA
            and action_pod.get("spec", {}).get("automountServiceAccountToken") is True
            and action_token_projected
            and action_pod.get("spec", {}).get("restartPolicy") == "Never"
            and action_pod.get("spec", {}).get("containers", [{}])[0].get("image") == image
            and action_pod.get("spec", {}).get("containers", [{}])[0].get("args") == action_args
            and consumer_permissions and action_permissions
            and consumer_subject_scoped and action_subject_scoped
            and consumer_role_ref and action_role_ref),
        "action_identity_cannot_update_the_owned_alternate_record": (
            action.get("alternate_action_status") == 403 and action_permissions
            and action_rule.get("rules") == [approved_rule]),
        "independent_readback_binds_updates_to_exact_owned_records": (
            approved_after.get("metadata", {}).get("uid") == approved_uid
            and approved_before.get("data", {}).get("status") == PENDING
            and approved_after.get("data", {}).get("status") == PROCESSED
            and approved_after.get("metadata", {}).get("resourceVersion") != approved_rv
            and alternate_after.get("metadata", {}).get("uid") == alternate_uid
            and alternate_after.get("metadata", {}).get("resourceVersion") == alternate_rv
            and alternate_after.get("data", {}).get("status") == PENDING
            and action.get("approved_update_returned_exact_uid") is True),
    }
    (lab.evidence / "downstream-authorization-raw.json").write_text(json.dumps({
        "scope": "two-owned-configmaps-fixed-status-action",
        "approved": {"before": approved_before, "after": approved_after},
        "alternate": {"before": alternate_before, "after": alternate_after},
        "consumer": consumer, "action": action,
        "pods": {"consumer": {"uid": approved_pod.get("metadata", {}).get("uid"),
                                "service_account": approved_pod.get("spec", {}).get("serviceAccountName"),
                                "phase": approved_pod.get("status", {}).get("phase"),
                                "projected_api_credential": consumer_token_projected},
                 "action": {"uid": action_pod.get("metadata", {}).get("uid"),
                            "service_account": action_pod.get("spec", {}).get("serviceAccountName"),
                            "phase": action_pod.get("status", {}).get("phase"),
                            "projected_api_credential": action_token_projected}},
        "roles": {"consumer": consumer_rule, "action": action_rule},
        "rolebindings": {"consumer": consumer_bind, "action": action_bind},
        "normalized": checks,
        "scope_limit": "Kubernetes RBAC is object-scoped; the client sends one fixed JSON Patch to data.status. No model, tool, external service, or arbitrary dispatch is exercised.",
    }, sort_keys=True, indent=2) + "\n")

    # Exact-name cleanup; the disposable namespace remains the final boundary.
    lab.kubectl("-n", NS, "delete", "pod", CONSUMER_POD, ACTION_POD,
                "--wait=true", timeout=35)
    lab.kubectl("-n", NS, "delete", "rolebinding", CONSUMER_ROLE, ACTION_ROLE,
                "--wait=true", timeout=25)
    lab.kubectl("-n", NS, "delete", "role", CONSUMER_ROLE, ACTION_ROLE,
                "--wait=true", timeout=25)
    lab.kubectl("-n", NS, "delete", "serviceaccount", CONSUMER_SA, ACTION_SA,
                "--wait=true", timeout=25)
    lab.kubectl("-n", NS, "delete", "configmap", APPROVED, ALTERNATE, CODE,
                "--wait=true", timeout=25)

    lab.check("supplement", "Native downstream action is independently authorized to one exact benign record",
              all(checks.values()), checks)
