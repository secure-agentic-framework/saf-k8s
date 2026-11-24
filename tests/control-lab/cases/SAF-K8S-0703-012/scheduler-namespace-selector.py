"""Verify required namespace-selector placement on the patched Kind control plane."""
import argparse
import json
from pathlib import Path
import re
import sys
import time

RUNNER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RUNNER))
import lab as harness
from fixtures import container, pod

CONTROL = "SAF-K8S-0703-012"
LOCAL_NODE_VERSION = "v1.36.6"
INCLUDED = "saf-scheduler-include"
EXCLUDED = "saf-scheduler-exclude"
ROLE = "fixture.saf/anchor"
COHORT = "fixture.saf/namespace-cohort"
NEGATIVE = {"matchExpressions": [{"key": COHORT, "operator": "NotIn", "values": ["outside"]}]}
SCOPE = (
    "One owned Kubernetes v1.36.6 Kind cluster. Two Ready workers host inert anchors "
    "in distinct labeled namespaces. Native required affinity and anti-affinity use "
    "the same label pair and compare a select-all namespace selector with NotIn under "
    "the patched scheduler. Test results cover one topology key and upstream patch."
)


def prepare_kind(_lab, temporary):
    profile = temporary / "scheduler-profile.json"
    profile.write_text(json.dumps({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
                                   "nodes": [{"role": "control-plane"}, {"role": "worker"}, {"role": "worker"}]}))
    return profile


def read(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def create_anchor(lab, namespace, worker):
    manifest = pod("namespace-anchor", [container("fixture")], automountServiceAccountToken=False,
                   nodeName=worker, terminationGracePeriodSeconds=1)
    manifest["metadata"]["labels"] = {ROLE: "namespace"}
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(manifest))
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/namespace-anchor",
                "--timeout=95s", timeout=105)
    return read(lab, "-n", namespace, "get", "pod", "namespace-anchor")


def schedule(lab, name, worker, affinity_key, selector):
    term = {"labelSelector": {"matchLabels": {ROLE: "namespace"}},
            "namespaceSelector": selector, "topologyKey": "kubernetes.io/hostname"}
    match_worker = {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
        {"matchFields": [{"key": "metadata.name", "operator": "In", "values": [worker]}]}
    ]}}
    affinity = {affinity_key: {"requiredDuringSchedulingIgnoredDuringExecution": [term]},
                "nodeAffinity": match_worker}
    lab.create(pod(name, [container("fixture")], automountServiceAccountToken=False,
                   terminationGracePeriodSeconds=1, affinity=affinity))
    deadline = time.monotonic() + 30
    while True:
        value = read(lab, "get", "pod", name)
        observed = next((x for x in value["status"].get("conditions", []) if x["type"] == "PodScheduled"), {})
        if observed.get("status") == "True":
            outcome = "scheduled" if value["spec"].get("nodeName") == worker else "wrong-node"
            break
        if observed.get("status") == "False" and observed.get("reason") == "Unschedulable":
            outcome = "unschedulable" if not value["spec"].get("nodeName") else "unexpected-binding"
            break
        if time.monotonic() >= deadline:
            lab.block(f"Scheduler did not decide the owned fixture Pod {name}")
        time.sleep(0.3)
    receipt = {"uid": value["metadata"]["uid"], "namespace": value["metadata"]["namespace"],
               "worker": worker, "node": value["spec"].get("nodeName"), "condition": observed,
               "affinity": value["spec"]["affinity"]}
    return outcome, receipt


def run(lab):
    lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=175s", timeout=185)
    nodes = read(lab, "get", "nodes")["items"]
    workers = sorted(x["metadata"]["name"] for x in nodes
                     if "node-role.kubernetes.io/control-plane" not in x["metadata"]["labels"]
                     and any(c["type"] == "Ready" and c["status"] == "True" for c in x["status"]["conditions"])
                     and not any(t["effect"] in ("NoSchedule", "NoExecute") for t in x["spec"].get("taints", [])))
    scheduler = read(lab, "-n", "kube-system", "get", "pods", "-l", "component=kube-scheduler")["items"]
    versions = sorted({x["status"]["nodeInfo"]["kubeletVersion"] for x in nodes})
    if len(nodes) != 3 or len(workers) != 2 or versions != [LOCAL_NODE_VERSION] or len(scheduler) != 1:
        lab.block("The expected one-control-plane, two-worker patched Kind topology is unavailable")
    scheduler_image = next(c["image"] for c in scheduler[0]["spec"]["containers"]
                           if c["name"] == "kube-scheduler")
    if not scheduler_image.endswith(f":{LOCAL_NODE_VERSION}"):
        lab.block("The observed scheduler image did not identify the selected Kubernetes patch")

    for namespace, cohort in ((INCLUDED, "inside"), (EXCLUDED, "outside")):
        lab.create({"apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": namespace, "labels": {COHORT: cohort}}})
    anchors = {name: create_anchor(lab, name, node) for name, node in zip((INCLUDED, EXCLUDED), workers)}
    observed_namespaces = {name: read(lab, "get", "namespace", name) for name in anchors}
    if [observed_namespaces[name]["metadata"]["labels"][COHORT] for name in (INCLUDED, EXCLUDED)] != [
        "inside", "outside"
    ]:
        lab.block("The observed fixture namespace labels differ")

    baseline = (
        ("red-affinity", workers[1], "podAffinity", {}, "scheduled"),
        ("red-anti-affinity", workers[1], "podAntiAffinity", {}, "unschedulable"),
    )
    selective = (
        ("green-affinity-excluded", workers[1], "podAffinity", NEGATIVE, "unschedulable"),
        ("green-anti-affinity-included", workers[0], "podAntiAffinity", NEGATIVE, "unschedulable"),
        ("positive-affinity-included", workers[0], "podAffinity", NEGATIVE, "scheduled"),
        ("positive-anti-affinity-excluded", workers[1], "podAntiAffinity", NEGATIVE, "scheduled"),
    )
    raw, outcomes = {}, {}
    for name, node, key, selector, expected in (*baseline, *selective):
        actual, raw[name] = schedule(lab, name, node, key, selector)
        outcomes[name] = actual
        lab.check(name.split("-", 1)[0], f"{name} produces the expected patched scheduler decision",
                  actual == expected, {"decision": actual, "expected": expected})
    normalized = {"control": CONTROL, "patch": LOCAL_NODE_VERSION, "node_count": len(nodes),
                  "scheduler_image": scheduler_image, "outcomes": outcomes}
    receipt = {"outcomes": normalized, "probes": raw,
               "anchors": {name: obj["metadata"]["uid"] for name, obj in anchors.items()},
               "namespaces": {name: obj["metadata"]["uid"] for name, obj in observed_namespaces.items()},
               "node_uids": [x["metadata"]["uid"] for x in nodes],
               "scheduler_uid": scheduler[0]["metadata"]["uid"]}
    for name, value in (("scheduler-namespace-selector-raw.json", receipt),
                        ("scheduler-namespace-selector-normalized.json", normalized)):
        (lab.evidence / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-node-image", required=True, help="Full Docker image ID of the verified Kind build")
    parser.add_argument("--docker-context", default="desktop-linux")
    parser.add_argument("--catalog-index", type=Path, default=RUNNER / "catalog/index.json")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.local_node_image):
        parser.error("Pass the full verified Docker image ID")
    index = json.loads(args.catalog_index.read_text())
    return harness.run(CONTROL, sys.modules[__name__], index, args.docker_context,
                       local_node_image=args.local_node_image)


if __name__ == "__main__":
    raise SystemExit(main())
