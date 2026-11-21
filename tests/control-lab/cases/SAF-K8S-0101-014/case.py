"""Observe live Node and RBAC decisions for two harmless ConfigMaps."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready
from lab import NAMESPACE


SCOPE = (
    "Self-managed kind Kubernetes v1.36.1 API server configured by kubeadm flags. "
    "Observe the effective Node and RBAC mode chain, narrow service-account "
    "authorization, and a node identity's access to a referenced ConfigMap."
)
ACCOUNT = "authz-probe"
ALLOWED = "authz-probe"
NEIGHBOR = "authz-neighbor"


def satisfies_baseline(modes):
    return {"Node", "RBAC"} <= set(modes) and not {"ABAC", "AlwaysAllow"} & set(modes)


def live_mode_chain(lab):
    pod_name = f"kube-apiserver-{lab.cluster}-control-plane"
    mirror = json.loads(lab.kubectl("-n", "kube-system", "get", f"pod/{pod_name}", "-o", "json").stdout)
    api_server = next(row for row in mirror["spec"]["containers"] if row["name"] == "kube-apiserver")
    args = api_server["command"] + api_server.get("args", [])
    flags = [arg.split("=", 1)[1] for arg in args if arg.startswith("--authorization-mode=")]
    if len(flags) != 1 or any(arg.split("=")[0] == "--authorization-config" for arg in args):
        lab.block("Expected exactly one kubeadm authorization-mode flag without structured configuration")
    return flags[0].split(",")


def request(lab, subject, groups, resource, *, wait_for_allow=False):
    impersonation = [f"--as={subject}", *[f"--as-group={group}" for group in groups]]
    deadline = time.monotonic() + 15
    while True:
        result = lab.kubectl(*impersonation, "get", *resource, "-o", "name",
                             allow_failure=True, timeout=12)
        if result.returncode == 0:
            return "allowed"
        if "(Forbidden)" not in result.stderr:
            lab.block("A ConfigMap authorization probe returned an unexpected response")
        if not wait_for_allow or time.monotonic() >= deadline:
            return "forbidden"
        time.sleep(0.5)


def grant_named_read(lab):
    api = "rbac.authorization.k8s.io/v1"
    identity = {"name": ACCOUNT, "namespace": NAMESPACE}
    lab.create({
        "apiVersion": api, "kind": "Role", "metadata": identity,
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [ALLOWED], "verbs": ["get"]}],
    })
    lab.create({
        "apiVersion": api, "kind": "RoleBinding", "metadata": identity,
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT},
        "subjects": [{"kind": "ServiceAccount", **identity}],
    })


def run(lab):
    fixtures = json.loads(Path(__file__).with_name("fixtures.json").read_text())
    for modes in fixtures["unsafe_static_only_examples"]:
        lab.check("red", "Configuration review identifies a prohibited authorizer",
                  not satisfies_baseline(modes), modes)
    lab.check("positive", "Configuration review accepts the requested baseline",
              satisfies_baseline(fixtures["safe_mode_chain"]), fixtures["safe_mode_chain"])
    observed = live_mode_chain(lab)
    lab.check("green", "The live API server uses the Node and RBAC baseline",
              satisfies_baseline(observed), observed)

    lab.kubectl("create", "serviceaccount", ACCOUNT)
    for name in (ALLOWED, NEIGHBOR):
        lab.kubectl("create", "configmap", name, "--from-literal=fixture=synthetic")
    account = f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"
    groups = ["system:authenticated", "system:serviceaccounts", f"system:serviceaccounts:{NAMESPACE}"]
    name = (f"configmap/{ALLOWED}",)
    before = request(lab, account, groups, name)
    lab.check("red", "The unbound account cannot get the existing test ConfigMap",
              before == "forbidden", before)

    grant_named_read(lab)
    after = request(lab, account, groups, name, wait_for_allow=True)
    lab.check("positive", "The same request succeeds after the named GET grant",
              after == "allowed", after)
    for resource in [(f"configmap/{NEIGHBOR}",), ("configmaps",)]:
        decision = request(lab, account, groups, resource)
        lab.check("green", f"The grant does not authorize kubectl get {resource[0]}",
                  decision == "forbidden", decision)

    node = f"{lab.cluster}-control-plane"
    node_subject = f"system:node:{node}"
    node_groups = ["system:nodes", "system:authenticated"]
    before = request(lab, node_subject, node_groups, name)
    lab.check("red", "The node cannot read a ConfigMap before a workload references it",
              before == "forbidden", before)
    workload = pod("node-authz-fixture", [
        container("probe", volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]),
    ], nodeName=node, automountServiceAccountToken=False,
        volumes=[{"name": "fixture", "configMap": {"name": ALLOWED}}])
    lab.create(workload)
    ready(lab, "node-authz-fixture")
    after = request(lab, node_subject, node_groups, name, wait_for_allow=True)
    lab.check("positive", "The node can get the ConfigMap mounted by its ready workload",
              after == "allowed", after)
    neighbor = request(lab, node_subject, node_groups, (f"configmap/{NEIGHBOR}",))
    lab.check("green", "The node still cannot read the unreferenced ConfigMap",
              neighbor == "forbidden", neighbor)
