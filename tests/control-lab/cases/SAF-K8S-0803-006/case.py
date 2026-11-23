"""Enforce separate delegated ownership of owned host and offload records."""

import json
import time

SCOPE = "Live Kubernetes RBAC isolation of synthetic policy records; no device or BMC management interface is used."
HOST = "fixture-host-operator"
DEVICE = "fixture-offload-operator"
HOST_RECORD = "fixture-host-policy"
DPU_RECORD = "fixture-offload-policy"
TEMP_BINDING = "fixture-shared-maintenance"
GROUP = "rbac.authorization.k8s.io"


def version(lab, name):
    return json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)["data"]["revision"]


def grant(lab, role, record, *, verbs):
    lab.create({"apiVersion": f"{GROUP}/v1", "kind": "Role", "metadata": {"name": role},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [record], "verbs": verbs}]})


def bind(lab, name, role, user):
    lab.create({"apiVersion": f"{GROUP}/v1", "kind": "RoleBinding", "metadata": {"name": name},
                "subjects": [{"kind": "User", "apiGroup": GROUP, "name": user}],
                "roleRef": {"kind": "Role", "apiGroup": GROUP, "name": role}})


def change(lab, user, record, revision):
    return lab.kubectl("--as", user, "patch", "configmap", record, "--type=merge",
                       "-p", json.dumps({"data": {"revision": revision}}), allow_failure=True)


def review(lab, user, record):
    result = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                         "spec": {"user": user, "resourceAttributes": {"namespace": "saf-test", "resource": "configmaps",
                                                                       "name": record, "verb": "patch"}}})
    return result["status"].get("allowed", False)


def run(lab):
    for name in (HOST_RECORD, DPU_RECORD):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"revision": "initial"}})
    grant(lab, "fixture-host-changes", HOST_RECORD, verbs=["get", "patch"])
    grant(lab, "fixture-offload-changes", DPU_RECORD, verbs=["get", "patch"])
    grant(lab, "fixture-offload-read", DPU_RECORD, verbs=["get"])
    bind(lab, "fixture-host-authorized", "fixture-host-changes", HOST)
    bind(lab, "fixture-offload-authorized", "fixture-offload-changes", DEVICE)
    bind(lab, "fixture-host-visible", "fixture-offload-read", HOST)
    bind(lab, TEMP_BINDING, "fixture-offload-changes", HOST)
    deadline = time.monotonic() + 20
    while not review(lab, HOST, DPU_RECORD):
        if time.monotonic() >= deadline:
            lab.block("The pre-control fixture role was not effective")
        time.sleep(0.4)
    baseline = change(lab, HOST, DPU_RECORD, "changed-under-shared-role").returncode == 0
    lab.check("red", "An overly broad shared maintenance role allows the modeled host operator to change the offload record",
              baseline and version(lab, DPU_RECORD) == "changed-under-shared-role", {"shared_role_allows_offload_edit": baseline})

    lab.kubectl("delete", "rolebinding", TEMP_BINDING)
    deadline = time.monotonic() + 20
    while review(lab, HOST, DPU_RECORD):
        if time.monotonic() >= deadline:
            lab.block("The delegated role change was not effective")
        time.sleep(0.4)
    rejected = change(lab, HOST, DPU_RECORD, "unapproved-change")
    denied = rejected.returncode != 0 and "forbidden" in rejected.stderr.lower()
    read = lab.kubectl("--as", HOST, "get", "configmap", DPU_RECORD, "-o", "json")
    visible = json.loads(read.stdout)["data"]["revision"] == "changed-under-shared-role"
    lab.check("green", "The host operator retains offload visibility while its offload write is denied",
              denied and visible, {"offload_write_denied": denied, "read_only_visibility_preserved": visible})

    host_ok = change(lab, HOST, HOST_RECORD, "approved-host").returncode == 0 and version(lab, HOST_RECORD) == "approved-host"
    device_ok = change(lab, DEVICE, DPU_RECORD, "approved-offload").returncode == 0 and version(lab, DPU_RECORD) == "approved-offload"
    lab.check("positive", "Each fixture administrator can update only its own policy scope",
              host_ok and device_ok and not review(lab, DEVICE, HOST_RECORD),
              {"approved_host_edit": host_ok, "approved_offload_edit": device_ok, "offload_admin_cannot_edit_host": True})
    (lab.evidence / "offload-rbac-observations.json").write_text(json.dumps({
        "shared_role_allows_offload_edit": baseline, "offload_write_denied": denied, "read_only_visibility_preserved": visible,
        "approved_host_edit": host_ok, "approved_offload_edit": device_ok, "device_management_tested": False}, indent=2) + "\n")
