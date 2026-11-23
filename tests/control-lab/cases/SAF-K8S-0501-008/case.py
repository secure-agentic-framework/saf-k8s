"""Exercise four workload-class NetworkPolicy segments on the lab's fresh kind cluster."""
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
import json
import time


NAMESPACES = {
    "training": "saf-0501-008-training",
    "inference": "saf-0501-008-inference",
    "pipeline": "saf-0501-008-pipeline",
    "notebook": "saf-0501-008-notebook",
}
CLASS_LABEL = "saf-k8s.example/workload-class"
POD_LABEL = "saf-k8s.example/role"
PORT = 8080
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
CLIENT = "client"
SERVER = "responder"
MARKERS = {kind: f"saf-0501-008-{kind}-fixed-marker" for kind in NAMESPACES}

# Each tuple is source class -> destination class. The other eight cross-class
# directions are expected to remain denied. Same-class paths are separately allowed.
ALLOWED_CROSS_CLASS = {
    ("training", "pipeline"),
    ("pipeline", "training"),
    ("pipeline", "inference"),
    ("notebook", "training"),
}
SCOPE = (
    "One disposable kind v0.32.0 cluster using its bundled kindnet and Kubernetes v1.36.1; "
    "four case-owned namespaces for training, inference, pipeline, and notebook, each with "
    "one non-root BusyBox client and one fixed-marker HTTP responder. The case verifies all "
    "12 directed cross-class IPv4 TCP/8080 paths before policy, then applies namespace-wide "
    "default-deny ingress and egress plus explicit selector-based ingress and egress rules. "
    "Four cross-class directions are allowed (training<->pipeline, pipeline->inference, "
    "notebook->training); the remaining eight are denied. One same-class path per namespace "
    "is also permitted. No Services, DNS, external targets, IPv6, other protocols, "
    "system namespaces, hostNetwork/node paths, production CNI, or cluster-wide policies "
    "are evaluated. A failed negative probe is attributed only to the controlled policy "
    "scenario after baseline reachability, healthy case-owned endpoints, and repeated "
    "timeout outcomes; the Kubernetes API does not identify a specific policy drop."
)


class ProbeAmbiguous(Exception):
    """A failed request did not produce the expected attributable network outcome."""


def _container(name, command):
    return {
        "name": name,
        "image": IMAGE,
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "75m", "memory": "24Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(namespace, workload_class, role, *, marker=None):
    if marker is None:
        command = ["sh", "-ec", "exec sleep 900"]
    else:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": role,
            "namespace": namespace,
            "labels": {CLASS_LABEL: workload_class, POD_LABEL: role},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [_container(role, command)],
            "terminationGracePeriodSeconds": 1,
        },
    }


def _create(lab, resource):
    lab.kubectl(
        "-n", resource["metadata"]["namespace"], "create", "-f", "-",
        payload=json.dumps(resource),
    )


def _network_policy(namespace, name, selector, policy_types, **rules):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": selector, "policyTypes": policy_types, **rules},
    }


def _class_peer(workload_class, role):
    # Both selectors in one peer object mean class AND role, per Kubernetes API semantics.
    return {
        "namespaceSelector": {"matchLabels": {CLASS_LABEL: workload_class}},
        "podSelector": {"matchLabels": {POD_LABEL: role}},
    }


def _install_policies(lab):
    for workload_class, namespace in NAMESPACES.items():
        _create(lab, _network_policy(
            namespace, "default-deny-ingress-egress", {}, ["Ingress", "Egress"],
        ))

    permitted = set(ALLOWED_CROSS_CLASS)
    permitted.update((workload_class, workload_class) for workload_class in NAMESPACES)
    for source_class, destination_class in sorted(permitted):
        source_ns = NAMESPACES[source_class]
        destination_ns = NAMESPACES[destination_class]
        edge = f"{source_class}-to-{destination_class}"
        # Ingress and egress both have to allow a connection. Keep both ends explicit.
        _create(lab, _network_policy(
            destination_ns,
            f"allow-ingress-{edge}",
            {"matchLabels": {POD_LABEL: SERVER}},
            ["Ingress"],
            ingress=[{
                "from": [_class_peer(source_class, CLIENT)],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        ))
        _create(lab, _network_policy(
            source_ns,
            f"allow-egress-{edge}",
            {"matchLabels": {POD_LABEL: CLIENT}},
            ["Egress"],
            egress=[{
                "to": [_class_peer(destination_class, SERVER)],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        ))


def _assert_policy_state(lab):
    expected = {namespace: {"default-deny-ingress-egress"} for namespace in NAMESPACES.values()}
    permitted = set(ALLOWED_CROSS_CLASS)
    permitted.update((workload_class, workload_class) for workload_class in NAMESPACES)
    for source_class, destination_class in sorted(permitted):
        edge = f"{source_class}-to-{destination_class}"
        expected[NAMESPACES[destination_class]].add(f"allow-ingress-{edge}")
        expected[NAMESPACES[source_class]].add(f"allow-egress-{edge}")
    snapshot = {}
    for namespace, names in expected.items():
        policies = json.loads(lab.kubectl(
            "-n", namespace, "get", "networkpolicies", "-o", "json",
        ).stdout).get("items", [])
        observed_names = {item.get("metadata", {}).get("name") for item in policies}
        if observed_names != names:
            lab.block(f"Case-owned NetworkPolicy state differs in {namespace}")
        snapshot[namespace] = sorted(observed_names)
    return snapshot


def _wait_pod(lab, namespace, name):
    lab.kubectl(
        "-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
        "--timeout=90s", timeout=100,
    )
    pod = json.loads(lab.kubectl(
        "-n", namespace, "get", "pod", name, "-o", "json",
    ).stdout)
    address = pod.get("status", {}).get("podIP")
    if not address:
        lab.block(f"Case-owned Pod {namespace}/{name} has no Pod IP")
    return str(IPv4Address(address))


def _assert_owned_pods_ready(lab):
    snapshot = {}
    for workload_class, namespace in NAMESPACES.items():
        for name in (CLIENT, SERVER):
            pod = json.loads(lab.kubectl(
                "-n", namespace, "get", "pod", name, "-o", "json",
            ).stdout)
            phase = pod.get("status", {}).get("phase")
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", [])
            )
            if phase != "Running" or not ready:
                lab.block(f"Case-owned endpoint {namespace}/{name} is not healthy")
            snapshot[f"{workload_class}/{name}"] = {
                "phase": phase, "ready": ready,
                "pod_ip": pod.get("status", {}).get("podIP"),
            }
    return snapshot


def _request(lab, source_class, destination_class, destination_ip):
    namespace = NAMESPACES[source_class]
    result = lab.kubectl(
        "-n", namespace, "exec", f"pod/{CLIENT}", "--", "wget", "-q", "-T", "2",
        "-O", "-", f"http://{destination_ip}:{PORT}/", allow_failure=True, timeout=14,
    )
    if result.returncode == 0:
        observed = result.stdout.strip()
        expected = MARKERS[destination_class]
        if observed != expected:
            lab.block("HTTP probe reached a case-owned listener but returned the wrong marker")
        return {"outcome": "marker", "marker": observed}
    combined = (result.stdout + result.stderr).lower()
    if "timed out" in combined or "timeout" in combined:
        return {"outcome": "timeout"}
    raise ProbeAmbiguous(
        f"{source_class}->{destination_class} failed without a timeout; "
        "policy attribution is ambiguous"
    )


def _observe_path(lab, source_class, destination_class, ips, allowed):
    # Repeat every expected result. Denials require three consecutive transport timeouts.
    # A timeout is only evidence in the context of the proven baseline and healthy endpoints.
    observations = []
    consecutive = 0
    expected_marker = MARKERS[destination_class]
    for _ in range(3):
        observation = _request(lab, source_class, destination_class, ips[destination_class])
        observations.append(observation)
        if allowed:
            if observation != {"outcome": "marker", "marker": expected_marker}:
                break
            consecutive += 1
        elif observation == {"outcome": "timeout"}:
            consecutive += 1
        else:
            break
        time.sleep(0.2)
    expected_outcome = "marker" if allowed else "timeout"
    matched = consecutive == 3 and len(observations) == 3
    return matched, {
        "source_class": source_class,
        "destination_class": destination_class,
        "expected_outcome": expected_outcome,
        "observations": observations,
        "three_consecutive_observations": matched,
        "transport": "IPv4 TCP",
        "destination_port": PORT,
        "controlled_endpoints_ready": True,
        "attribution_limit": (
            "controlled policy scenario; NetworkPolicy API does not identify a specific drop"
        ) if not allowed else "fixed marker returned by the selected case-owned responder",
    }


def _check_paths(lab, addresses, paths):
    # Independent short reads run concurrently while receipts stay ordered.
    with ThreadPoolExecutor(max_workers=4) as pool:
        observations = [
            pool.submit(_observe_path, lab, source, destination, addresses, allowed)
            for source, destination, allowed, _, _ in paths
        ]
        for (_, _, _, phase, label), observed in zip(paths, observations):
            matched, receipt = observed.result()
            lab.check(phase, label, matched, receipt)


def _check_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, got {kind_version!r}")
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    daemonset = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json",
    ).stdout)
    images = [c["image"] for c in daemonset["spec"]["template"]["spec"]["containers"]]
    if not any("kindnetd" in image for image in images):
        lab.block("The ready kube-system/kindnet daemonset does not identify a kindnetd image")
    lab.check("positive", "Runner is kind v0.32.0 / Kubernetes v1.36.1 with ready bundled kindnet",
              True, {"kind_version": kind_version, "kubernetes_version": server_version,
                     "daemonset": "kube-system/kindnet", "images": images})


def run(lab):
    _check_platform(lab)
    addresses = {}
    for workload_class, namespace in NAMESPACES.items():
        lab.kubectl("create", "namespace", namespace)
        lab.kubectl("label", "namespace", namespace, f"{CLASS_LABEL}={workload_class}")
        _create(lab, _pod(namespace, workload_class, CLIENT))
        _create(lab, _pod(namespace, workload_class, SERVER, marker=MARKERS[workload_class]))
        addresses[workload_class] = _wait_pod(lab, namespace, SERVER)
        _wait_pod(lab, namespace, CLIENT)

    # Red phase: exact source and destination Pods and fixed marker responders, all 12 paths.
    _assert_owned_pods_ready(lab)
    classes = tuple(NAMESPACES)
    directed = [(source, destination) for source in classes for destination in classes
                if source != destination]
    _check_paths(lab, addresses, [
        (source, destination, True, "red",
         f"No-policy baseline reaches {destination} from {source} with its marker")
        for source, destination in directed
    ])

    # Install deny and explicit paired ingress/egress rules, then allow policy convergence.
    for workload_class, namespace in NAMESPACES.items():
        # Retain the marker as controlled state showing the namespace label used by policy peers.
        observed = json.loads(lab.kubectl(
            "get", "namespace", namespace, "-o", "json",
        ).stdout)
        if observed.get("metadata", {}).get("labels", {}).get(CLASS_LABEL) != workload_class:
            lab.block(f"Namespace {namespace} is missing its expected workload-class label")
    _install_policies(lab)
    time.sleep(3)
    _assert_owned_pods_ready(lab)
    policy_state = _assert_policy_state(lab)

    paths = []
    for source, destination in directed:
        allowed = (source, destination) in ALLOWED_CROSS_CLASS
        paths.append((source, destination, allowed, "positive" if allowed else "green",
                      f"Policy matrix {'allows' if allowed else 'denies'} {source}->{destination}"))
    for workload_class in classes:
        paths.append((workload_class, workload_class, True, "positive",
                      f"Explicit same-class path remains useful in {workload_class}"))
    _check_paths(lab, addresses, paths)

    ready_state = _assert_owned_pods_ready(lab)
    stable_status = {key: {"phase": value["phase"], "ready": value["ready"]}
                     for key, value in ready_state.items()}
    lab.check("positive", "All case-owned clients and responders remain ready after the matrix",
              len(stable_status) == 8, {"pod_readiness": stable_status,
                                       "network_policies_by_namespace": policy_state})
    (lab.evidence / "workload-paths.raw.json").write_text(json.dumps(
        {"pods": ready_state, "policy_names_by_namespace": policy_state},
        indent=2, sort_keys=True) + "\n")
