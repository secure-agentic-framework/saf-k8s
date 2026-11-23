"""Measure the Node-object visibility boundary around a synthetic topology label."""

import json
import time

SCOPE = "Live Kubernetes Node visibility for one synthetic label with a separate visible fixture Pod placement field."
RBAC = "rbac.authorization.k8s.io"
LABEL = "fixture.example/accelerator-model"
VALUE = "synthetic-topology-marker"
READER = "fixture-topology-reader"
TENANT = "fixture-tenant-reader"
POD = "fixture-tenant-workload"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def bind_node_reader(lab, name, user):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRoleBinding", "metadata": {"name": name},
                "roleRef": {"apiGroup": RBAC, "kind": "ClusterRole", "name": "fixture-topology-reader"},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user}]})


def list_nodes(lab, user):
    result = lab.kubectl("--as", user, "get", "nodes", "-o", "json", allow_failure=True)
    if result.returncode == 0:
        return {"node_list_allowed": True, "label_present": any(
            row["metadata"].get("labels", {}).get(LABEL) == VALUE for row in json.loads(result.stdout)["items"])}
    if "(Forbidden)" not in result.stderr or 'resource "nodes"' not in result.stderr:
        lab.block("The live Node API did not return an attributable authorization decision")
    return {"node_list_allowed": False, "label_present": False}


def tenant_pod(lab):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": "fixture-tenant-reader"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "resourceNames": [POD], "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": "fixture-tenant-reader"},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": "fixture-tenant-reader"},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": TENANT}]})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
                "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                         "containers": [{"name": "inert", "image": IMAGE,
                                         "command": ["python", "-c", "import time; time.sleep(90)"]}]}})
    lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{POD}", "--timeout=35s", timeout=45)
    response = lab.kubectl("--as", TENANT, "get", "pod", POD, "-o", "json")
    return bool(json.loads(response.stdout)["spec"].get("nodeName"))


def run(lab):
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    lab.kubectl("label", "node", node["metadata"]["name"], f"{LABEL}={VALUE}")
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRole", "metadata": {"name": "fixture-topology-reader"},
                "rules": [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["list"]}]})
    bind_node_reader(lab, "fixture-authorized-topology", READER)
    bind_node_reader(lab, "fixture-extra-topology", TENANT)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        before = list_nodes(lab, TENANT)
        if before["label_present"]:
            break
        time.sleep(0.4)
    lab.check("red", "A Node list grant exposes the synthetic topology label through the real Node API",
              before == {"node_list_allowed": True, "label_present": True}, before)
    lab.kubectl("delete", "clusterrolebinding", "fixture-extra-topology")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        after = list_nodes(lab, TENANT)
        if not after["node_list_allowed"]:
            break
        time.sleep(0.4)
    lab.check("green", "Revoking the excess grant denies the whole Node list to the tenant",
              after == {"node_list_allowed": False, "label_present": False}, after)

    authorized = list_nodes(lab, READER)
    placement = tenant_pod(lab)
    lab.check("positive", "A separate operator still sees the label and the tenant still sees its own Pod placement",
              authorized["label_present"] and placement, {"authorized_label_visible": authorized["label_present"],
              "tenant_pod_placement_visible": placement})
    (lab.evidence / "topology-observations.json").write_text(json.dumps(
        {"before": before, "after": after, "authorized_reader": authorized, "tenant_pod_placement_visible": placement,
         "topology_label_is_synthetic": True}, indent=2) + "\n")
