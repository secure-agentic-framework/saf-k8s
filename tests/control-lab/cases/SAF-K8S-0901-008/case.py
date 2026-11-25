"""Demonstrate a scoped egress allowlist for a synthetic training worker."""
import json
import time

from fixtures import container, pod


CONTROL_ID = "SAF-K8S-0901-008"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
KIND_VERSION = "kind v0.32.0"
PORT = 8080
TRAINING_NS = "saf-0901-008-training"
AUTHORIZED_NS = "saf-0901-008-authorized"
UNAUTHORIZED_NS = "saf-0901-008-peer"
POSITIVE_NS = "saf-0901-008-positive"
WORKER = "mock-training-worker"
AUTHORIZED = "mock-authorized-peer"
UNAUTHORIZED = "mock-unapproved-peer"
WRONG_LABEL = "mock-unapproved-label"
POSITIVE_CLIENT = "mock-positive-client"
POSITIVE_TARGET = "mock-positive-target"
MARKERS = {
    AUTHORIZED: "SYNTH-0901-008-AUTHORIZED-HTTP",
    UNAUTHORIZED: "SYNTH-0901-008-UNAUTHORIZED-HTTP",
    POSITIVE_TARGET: "SYNTH-0901-008-POSITIVE-CONTROL-HTTP",
    WRONG_LABEL: "SYNTH-0901-008-WRONG-LABEL-HTTP",
    "mock-training-marker-target": "SYNTH-0901-008-CROSS-NODE-TRAINING-MARKER",
}
SCOPE = (
    "One disposable two-node Kind Kubernetes v1.36.1 cluster using Kind v0.32.0's "
    "bundled kindnet and its native NetworkPolicy implementation. Digest-pinned BusyBox "
    "Pods provide one synthetic training worker, harmless HTTP peers across two separate "
    "fixture namespaces, and an independent positive-control client/listener. Before/after "
    "ordinary IPv4 TCP/8080 requests show baseline reachability, an exact worker egress "
    "allowlist to one namespace-and-pod selector, denied namespace and Pod-label near misses, and "
    "an unaffected positive path plus one ordinary cross-node Pod TCP marker path. No RDMA, NCCL, "
    "GPU, encryption, VLAN/fabric enforcement, external traffic, DNS, IPv6, hostNetwork, "
    "or production workload is exercised."
)


def labels(name):
    return {"saf-lab.example/control": CONTROL_ID, "saf-lab.example/fixture": name}


def namespace(name, role):
    return {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": name, "labels": {
            "saf-lab.example/control": CONTROL_ID,
            "saf-lab.example/fixture": "synthetic-only",
            "saf-lab.example/role": role,
        }},
    }


def add_resource(lab, resource):
    target = resource["metadata"].get("namespace")
    scoped = ("-n", target) if target else ()
    lab.kubectl(*scoped, "create", "-f", "-", payload=json.dumps(resource))


def make_pod(name, namespace_name, *, marker=None, role=None):
    if marker:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    else:
        command = ["sleep", "900"]
    workload = pod(
        name,
        [container("fixture", command=command, image=IMAGE,
                   resources={"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}})],
        automountServiceAccountToken=False,
    )
    workload["metadata"].update(namespace=namespace_name, labels=labels(role or name))
    workload["spec"]["securityContext"] = {
        "runAsNonRoot": True, "runAsUser": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    return workload


def create_pod(lab, name, namespace_name, *, marker=None, role=None):
    add_resource(lab, make_pod(name, namespace_name, marker=marker, role=role))
    lab.kubectl("-n", namespace_name, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl(
        "-n", namespace_name, "get", f"pod/{name}", "-o", "json").stdout)
    if not current.get("status", {}).get("podIP"):
        lab.block(f"Synthetic fixture Pod {namespace_name}/{name} has no Pod IP")
    return current["status"]["podIP"]


def create_node_pinned_pod(lab, name, namespace_name, node, *, marker=None, role=None):
    workload = make_pod(name, namespace_name, marker=marker, role=role)
    workload["spec"]["nodeSelector"] = {"kubernetes.io/hostname": node}
    workload["spec"]["tolerations"] = [
        {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
         "effect": "NoSchedule"},
    ]
    add_resource(lab, workload)
    lab.kubectl("-n", namespace_name, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    return json.loads(lab.kubectl(
        "-n", namespace_name, "get", f"pod/{name}", "-o", "json").stdout)


def is_ready(resource):
    return any(condition.get("type") == "Ready" and condition.get("status") == "True"
               for condition in resource.get("status", {}).get("conditions", []))


def policy_object():
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "training-worker-egress-allowlist", "namespace": TRAINING_NS,
                     "labels": labels("training-worker-egress-policy")},
        "spec": {
            "podSelector": {"matchLabels": {"saf-lab.example/fixture": "training-worker"}},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "saf-lab.example/role": "authorized-training-peer"}},
                    "podSelector": {"matchLabels": {
                        "saf-lab.example/fixture": "authorized-training-peer"}},
                }],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        },
    }


def observed_policy_is_exact(observed):
    actual = observed.get("spec", {})
    expected = policy_object()["spec"]
    return actual == expected and observed.get("metadata", {}).get("namespace") == TRAINING_NS


def request(lab, source_ns, source_pod, destination_ip, expected_marker):
    result = lab.kubectl(
        "-n", source_ns, "exec", f"pod/{source_pod}", "--", "wget", "-T", "2",
        "-O", "-", f"http://{destination_ip}:{PORT}/", allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != expected_marker:
            lab.block("HTTP probe reached a fixture listener but got an unexpected marker")
        return {"reachable": True, "marker_matches": True, "outcome": "HTTP 200 fixed marker"}
    combined = (result.stdout + result.stderr).lower()
    if any(reason in combined for reason in (
            "timed out", "connection refused", "no route to host", "network is unreachable")):
        return {"reachable": False, "marker_matches": False, "outcome": "TCP request failed"}
    lab.block("HTTP probe failed without a recognized network outcome")


def expect_path(lab, phase, name, source_ns, source_pod, destination_ip, marker, allowed, claim):
    deadline = time.monotonic() + 30
    consecutive = 0
    last = None
    while time.monotonic() < deadline:
        last = request(lab, source_ns, source_pod, destination_ip, marker)
        consecutive = consecutive + 1 if last["reachable"] is allowed else 0
        if consecutive >= 2:
            break
        time.sleep(0.5)
    observed = {
        "path": name, "source": f"{source_ns}/{source_pod}",
        "destination_pod_ip": destination_ip, "protocol": "IPv4 TCP",
        "destination_port": PORT, "expected_reachable": allowed,
        "last_observation": last, "two_consecutive_observations": consecutive >= 2,
    }
    lab.check(phase, claim, consecutive >= 2,
              {key: value for key, value in observed.items() if key != "destination_pod_ip"})
    return observed


def check_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith(KIND_VERSION):
        lab.block(f"Expected {KIND_VERSION} with bundled policy-capable kindnet, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    daemonset = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset/kindnet", "-o", "json").stdout)
    images = [item["image"] for item in daemonset["spec"]["template"]["spec"]["containers"]]
    if not any("kindnetd" in image for image in images):
        lab.block("The expected bundled kindnet DaemonSet was not identified")
    observed = {"kind_version": kind_version, "kubernetes_version": server.get("gitVersion"),
                "kind_node_image": NODE_IMAGE, "kindnet_daemonset": "kube-system/kindnet",
                "kindnet_images": images}
    lab.check("positive", "Pinned Kind profile and ready bundled kindnet are identified", True, observed)
    return observed


def run(lab):
    platform = check_platform(lab)
    for name, role in (
        (TRAINING_NS, "synthetic-training"),
        (AUTHORIZED_NS, "authorized-training-peer"),
        (UNAUTHORIZED_NS, "unapproved-peer"),
        (POSITIVE_NS, "independent-positive-control"),
    ):
        add_resource(lab, namespace(name, role))

    authorized_ip = create_pod(
        lab, AUTHORIZED, AUTHORIZED_NS, marker=MARKERS[AUTHORIZED], role="authorized-training-peer")
    unauthorized_ip = create_pod(
        lab, UNAUTHORIZED, UNAUTHORIZED_NS, marker=MARKERS[UNAUTHORIZED], role="authorized-training-peer")
    positive_ip = create_pod(
        lab, POSITIVE_TARGET, POSITIVE_NS, marker=MARKERS[POSITIVE_TARGET], role="positive-target")
    create_pod(lab, WORKER, TRAINING_NS, role="training-worker")
    create_pod(lab, POSITIVE_CLIENT, POSITIVE_NS, role="positive-client")

    source_node = f"{lab.cluster}-control-plane"
    target_node = f"{lab.cluster}-worker"
    wrong_label_pod = create_node_pinned_pod(
        lab, WRONG_LABEL, AUTHORIZED_NS, target_node,
        marker=MARKERS[WRONG_LABEL], role="unapproved-label")
    wrong_label_ip = wrong_label_pod.get("status", {}).get("podIP")
    marker_source = create_node_pinned_pod(
        lab, "mock-training-marker-source", TRAINING_NS, source_node,
        role="training-worker")
    marker_target = create_node_pinned_pod(
        lab, "mock-training-marker-target", AUTHORIZED_NS, target_node,
        marker=MARKERS["mock-training-marker-target"], role="authorized-training-peer")
    node_records = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout).get("items", [])
    nodes = {node.get("metadata", {}).get("name"): node for node in node_records}
    source_actual_node = marker_source.get("spec", {}).get("nodeName")
    target_actual_node = marker_target.get("spec", {}).get("nodeName")
    wrong_label_actual_node = wrong_label_pod.get("spec", {}).get("nodeName")
    placed_ready = (
        source_actual_node == source_node and target_actual_node == target_node
        and source_actual_node != target_actual_node
        and wrong_label_actual_node == target_node
        and source_actual_node in nodes and target_actual_node in nodes
        and is_ready(nodes[source_actual_node]) and is_ready(nodes[target_actual_node])
        and all(is_ready(pod) for pod in (marker_source, marker_target, wrong_label_pod))
        and bool(marker_source.get("status", {}).get("podIP"))
        and bool(marker_target.get("status", {}).get("podIP"))
        and bool(wrong_label_pod.get("status", {}).get("podIP"))
    )
    lab.check("positive", "Training marker Pods are Ready on distinct Ready owned Kind nodes",
              placed_ready,
              {"source_is_control_plane": source_actual_node == source_node,
               "target_is_worker": target_actual_node == target_node,
               "nodes_distinct": source_actual_node != target_actual_node,
               "source_node_ready": bool(source_actual_node in nodes and is_ready(nodes[source_actual_node])),
               "target_node_ready": bool(target_actual_node in nodes and is_ready(nodes[target_actual_node])),
               "wrong_label_peer_on_worker_node": wrong_label_actual_node == target_node,
               "wrong_label_peer_node_ready": bool(target_node in nodes and is_ready(nodes[target_node])),
               "source_pod_ready": is_ready(marker_source), "target_pod_ready": is_ready(marker_target),
               "wrong_label_peer_ready": is_ready(wrong_label_pod)})

    observations = {"platform": platform, "image": IMAGE, "port": PORT, "red": {}, "green": {}}
    observations["red"]["worker_to_authorized_peer"] = expect_path(
        lab, "red", "worker_to_authorized_peer", TRAINING_NS, WORKER, authorized_ip,
        MARKERS[AUTHORIZED], True,
        "Before policy, the mock training worker reaches the authorized fixture listener")
    observations["red"]["worker_to_unapproved_peer"] = expect_path(
        lab, "red", "worker_to_unapproved_peer", TRAINING_NS, WORKER, unauthorized_ip,
        MARKERS[UNAUTHORIZED], True,
        "Before policy, the same worker reaches the peer in another fixture namespace")
    observations["red"]["worker_to_wrong_label"] = expect_path(
        lab, "red", "worker_to_wrong_label", TRAINING_NS, WORKER, wrong_label_ip,
        MARKERS[WRONG_LABEL], True,
        "Before policy, the worker reaches a differently labeled peer in the authorized namespace")
    observations["red"]["independent_positive_control"] = expect_path(
        lab, "red", "independent_positive_control", POSITIVE_NS, POSITIVE_CLIENT, positive_ip,
        MARKERS[POSITIVE_TARGET], True,
        "Independent positive-control Pods reach their harmless listener before policy")
    observations["red"]["cross_node_training_marker"] = expect_path(
        lab, "red", "cross_node_training_marker", TRAINING_NS,
        "mock-training-marker-source", marker_target.get("status", {}).get("podIP"),
        MARKERS["mock-training-marker-target"], True,
        "Before policy, the training marker source reaches its distinct-node target")
    observations["red"]["cross_node_wrong_label"] = expect_path(
        lab, "red", "cross_node_wrong_label", TRAINING_NS,
        "mock-training-marker-source", wrong_label_ip, MARKERS[WRONG_LABEL], True,
        "Before policy, the same control-plane marker source reaches the worker-node wrong-label peer")

    desired = policy_object()
    add_resource(lab, desired)
    observations["green"]["worker_to_authorized_peer"] = expect_path(
        lab, "green", "worker_to_authorized_peer", TRAINING_NS, WORKER, authorized_ip,
        MARKERS[AUTHORIZED], True,
        "Worker allowlist preserves TCP/8080 to the authorized labeled fixture peer")
    observations["green"]["worker_to_unapproved_peer"] = expect_path(
        lab, "green", "worker_to_unapproved_peer", TRAINING_NS, WORKER, unauthorized_ip,
        MARKERS[UNAUTHORIZED], False,
        "Worker egress policy denies TCP/8080 to a peer in a different fixture namespace")
    observations["green"]["worker_to_wrong_label"] = expect_path(
        lab, "green", "worker_to_wrong_label", TRAINING_NS, WORKER, wrong_label_ip,
        MARKERS[WRONG_LABEL], False,
        "The worker policy denies a differently labeled peer even in the authorized namespace")
    observations["green"]["unselected_to_denied_destination"] = expect_path(
        lab, "positive", "unselected_to_denied_destination", POSITIVE_NS, POSITIVE_CLIENT,
        unauthorized_ip, MARKERS[UNAUTHORIZED], True,
        "An unselected client still reaches the same peer the training worker cannot reach")
    observations["green"]["independent_positive_control"] = expect_path(
        lab, "positive", "independent_positive_control", POSITIVE_NS, POSITIVE_CLIENT, positive_ip,
        MARKERS[POSITIVE_TARGET], True,
        "Unselected positive-control Pods remain independently reachable after worker isolation")
    observations["green"]["cross_node_training_marker"] = expect_path(
        lab, "green", "cross_node_training_marker", TRAINING_NS,
        "mock-training-marker-source", marker_target.get("status", {}).get("podIP"),
        MARKERS["mock-training-marker-target"], True,
        "The exact worker and authorized-peer selectors preserve the distinct-node training marker path")
    observations["green"]["cross_node_wrong_label"] = expect_path(
        lab, "green", "cross_node_wrong_label", TRAINING_NS,
        "mock-training-marker-source", wrong_label_ip, MARKERS[WRONG_LABEL], False,
        "The exact allowlist blocks that same cross-node path to the wrong-label peer")

    live = json.loads(lab.kubectl(
        "-n", TRAINING_NS, "get", "networkpolicy", "training-worker-egress-allowlist", "-o", "json").stdout)
    exact = observed_policy_is_exact(live)
    observations["policy"] = {
        "namespace": live.get("metadata", {}).get("namespace"),
        "name": live.get("metadata", {}).get("name"),
        "spec": live.get("spec"),
        "exact_expected_worker_and_peer_selectors_and_tcp_port": exact,
    }
    lab.check("positive", "API read confirms the exact scoped worker and peer allowlist", exact,
              observations["policy"])
    observations["boundary"] = (
        "Synthetic metadata and fixed HTTP markers only; no credentials, tokens, Secret data, "
        "external target, feed, scan, or workload content. Two-node ordinary Pod traffic only; no RDMA, NCCL, GPU, or fabric proof."
    )
    (lab.evidence / "training-networkpolicy-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
