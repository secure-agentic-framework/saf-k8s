"""Exercise actual DaemonSet scheduling and per-node fixture log collection."""
import json
from pathlib import Path
import time

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
ROLES = ("control-plane", "worker", "worker2")
NAMESPACE = "saf-test"
DAEMONSET = "saf-node-log-collector"
MARKERS = "/var/lib/saf-k8s-1001-032/markers"
ACCELERATOR = "saf-k8s.example/accelerator"
CONTROL_TOLERATION = {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}
ACCELERATOR_TOLERATION = {"key": ACCELERATOR, "operator": "Equal", "value": "true", "effect": "NoSchedule"}
SECURITY = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}}
POD_SECURITY = {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
SCOPE = (
    "One disposable v1.36.1 cluster with a control plane and two workers. A real "
    "DaemonSet reads the distinct read-only owned marker and actual fixture Pod "
    "logs on each covered node. One worker has a synthetic accelerator NoSchedule "
    "taint. GPU hardware/driver and cloud-provider collection require separate evidence."
)


def prepare_kind(_lab, temporary):
    nodes = []
    for role in ROLES:
        marker_path = temporary / role
        marker_path.mkdir()
        (marker_path / "marker.txt").write_text(f"saf032-node-{role}\n")
        nodes.append({
            "role": "control-plane" if role == "control-plane" else "worker",
            "extraMounts": [{"hostPath": str(marker_path), "containerPath": MARKERS, "readOnly": True}],
        })
    path = temporary / "kind.yaml"
    path.write_text(json.dumps({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": nodes}))
    return path


def apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def sources(lab, nodes):
    identities = {}
    for role, node in nodes.items():
        name = f"saf032-source-{role}"
        identities[node] = name
        text = f"saf032-stdout-{role}"
        lab.create({
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {
                "automountServiceAccountToken": False, "securityContext": POD_SECURITY,
                "nodeSelector": {"kubernetes.io/hostname": node},
                "tolerations": [CONTROL_TOLERATION, ACCELERATOR_TOLERATION],
                "containers": [{"name": "source", "image": IMAGE, "securityContext": SECURITY,
                                "command": ["python","-u","-c",
                                            "import sys,time; print(sys.argv[1],flush=True); time.sleep(3600)", text]}],
            },
        })
    for role, node in nodes.items():
        name = identities[node]
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=75s", timeout=85)
        contents = lab.kubectl("logs", f"pod/{name}", "-c", "source").stdout.strip()
        if contents != f"saf032-stdout-{role}":
            lab.block(f"Fixture workload {name} did not write its known stdout marker")
    return identities


def install_collector_identity(lab, identities):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": DAEMONSET}})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": DAEMONSET},
                "rules": [{"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"],
                           "resourceNames": sorted(identities.values())}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": DAEMONSET},
                "subjects": [{"kind": "ServiceAccount", "name": DAEMONSET, "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": DAEMONSET}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": DAEMONSET},
                "immutable": True, "data": {"collector.py": (HERE/"collector.py").read_text(),
                                             "pods.json": json.dumps(identities)}})


def daemonset(lab, allow_accelerator):
    tolerations = [CONTROL_TOLERATION]
    if allow_accelerator:
        tolerations.append(ACCELERATOR_TOLERATION)
    labels = {"app": DAEMONSET}
    apply(lab, {
        "apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": DAEMONSET},
        "spec": {"selector": {"matchLabels": labels}, "template": {
            "metadata": {"labels": labels}, "spec": {
                "serviceAccountName": DAEMONSET, "securityContext": POD_SECURITY, "tolerations": tolerations,
                "containers": [{
                    "name": "collector", "image": IMAGE, "command": ["python","-u","/sources/collector.py"],
                    "securityContext": SECURITY,
                    "env": [{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}],
                    "volumeMounts": [{"name": "marker", "mountPath": "/owned-marker", "readOnly": True},
                                     {"name": "sources", "mountPath": "/sources", "readOnly": True}],
                }],
                "volumes": [{"name": "marker", "hostPath": {"path": MARKERS, "type": "Directory"}},
                            {"name": "sources", "configMap": {"name": DAEMONSET}}],
            },
        }},
    })
    lab.kubectl("rollout", "status", f"daemonset/{DAEMONSET}", "--timeout=90s", timeout=100)


def collect(lab, nodes, target, phase):
    by_node = {node: role for role, node in nodes.items()}
    deadline = time.monotonic() + 40
    raw = {}
    while time.monotonic() < deadline:
        pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={DAEMONSET}", "-o", "json").stdout)["items"]
        raw = {}
        for pod in pods:
            if pod["metadata"].get("deletionTimestamp") or not pod["spec"].get("nodeName"):
                continue
            role = by_node[pod["spec"]["nodeName"]]
            logs = lab.kubectl("logs", f"pod/{pod['metadata']['name']}", "--tail=8", allow_failure=True)
            raw[role] = [json.loads(line) for line in logs.stdout.splitlines() if line] if logs.returncode == 0 else []
        exact = {
            role: {"marker": f"saf032-node-{role}", "workload": f"saf032-stdout-{role}"}
            for role, logs in raw.items()
            if {"node": nodes[role], "node_marker": f"saf032-node-{role}",
                "workload_lines": [f"saf032-stdout-{role}"]} in logs
        }
        if set(exact) == target and set(raw) == target:
            break
        time.sleep(1)
    (lab.evidence / f"{phase}.raw-collector.json").write_text(json.dumps(raw, indent=2, sort_keys=True)+"\n")
    ds = json.loads(lab.kubectl("get", f"daemonset/{DAEMONSET}", "-o", "json").stdout)["status"]
    return {"sources": exact, "collector_nodes": sorted(raw),
            "desired": ds["desiredNumberScheduled"], "ready": ds["numberReady"]}


def run(lab):
    nodes = {role: f"{lab.cluster}-{role}" for role in ROLES}
    lab.kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=90s", timeout=100)
    lab.kubectl("label", "node", nodes["worker2"], f"{ACCELERATOR}=true")
    lab.kubectl("taint", "node", nodes["worker2"], f"{ACCELERATOR}=true:NoSchedule")
    identities = sources(lab, nodes)
    lab.check("positive", "Owned Pod log sources are live on all nodes before collection",
              set(identities) == set(nodes.values()), {"source_roles": sorted(nodes)})
    install_collector_identity(lab, identities)
    daemonset(lab, False)
    expect_before = set(ROLES) - {"worker2"}
    before = collect(lab, nodes, expect_before, "baseline")
    lab.check("red", "The untolerated accelerator worker misses both collector sources",
              before["collector_nodes"] == sorted(expect_before) and set(before["sources"]) == expect_before
              and before["desired"] == before["ready"] == 2, before)
    daemonset(lab, True)
    after = collect(lab, nodes, set(ROLES), "covered")
    lab.check("green", "The exact toleration covers all nodes and collects both sources from each",
              after["collector_nodes"] == sorted(ROLES) and set(after["sources"]) == set(ROLES)
              and after["desired"] == after["ready"] == 3, after)
