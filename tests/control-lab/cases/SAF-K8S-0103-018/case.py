"""Check a three-member kind control plane and bounded single-node maintenance."""
import json
import time
from pathlib import Path


HERE = Path(__file__).parent
FIXTURE_FILE = HERE / "failure-domain-fixtures.json"
NAMESPACE = "saf-test"
CONFIGMAP = "saf-0103-018-maintenance-probe"
PROBE_KEY = "probe"
PROBE_VALUE = "synthetic-write-after-one-control-plane-stop"
ETCD_ENDPOINT = "https://127.0.0.1:2379"
ETCD_CERTS = "/etc/kubernetes/pki/etcd"
EXPECTED_ETCD_IMAGE = "registry.k8s.io/etcd:3.6.8-0"
CONTROL_PLANES = ("control-plane", "control-plane2", "control-plane3")
COMPONENTS = ("kube-apiserver", "kube-controller-manager", "kube-scheduler")

SCOPE = (
    "One disposable local kind Kubernetes v1.36.1 cluster with three configured and "
    "observed control-plane nodes. Verify three Ready Kubernetes control-plane "
    "component replicas and exactly three ready kubeadm static etcd "
    "members, their member IDs/names/peer URLs, per-member endpoint health and "
    "readiness, then stop and restart only one case-owned control-plane container "
    "for a bounded API health and synthetic ConfigMap read/write probe. Separate "
    "synthetic failure-domain fixtures demonstrate replica concentration versus "
    "three-domain placement and odd-member quorum arithmetic. Container placement "
    "does not establish distinct physical failure domains; worker capacity, external "
    "etcd, managed Kubernetes guarantees, production availability, and real domain "
    "failure are outside scope."
)


def kubectl(lab, *args, timeout=30, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={timeout - 5}s", *args, timeout=timeout,
        allow_failure=allow_failure,
    )


def expected_quorum(members):
    return members // 2 + 1


def check_fixtures(lab):
    fixture = json.loads(FIXTURE_FILE.read_text())
    scenarios = {row["name"]: row for row in fixture["scenarios"]}
    red = scenarios["red-concentrated-control-plane"]
    green = scenarios["green-one-member-per-synthetic-domain"]

    def modeled(scenario):
        survivors = sum(member["synthetic_failure_domain"] != scenario["loss_domain"]
                        for member in scenario["members"])
        quorum = expected_quorum(len(scenario["members"]))
        available = survivors >= quorum
        return survivors, quorum, available

    red_observed = modeled(red)
    lab.check(
        "red", "Loss of the concentrated synthetic domain leaves fewer than quorum",
        red_observed == (red["surviving_members"], red["expected_quorum"],
                         red["expected_available"]),
        {"fixture": red["name"], "survivors": red_observed[0],
         "quorum": red_observed[1], "available": red_observed[2],
         "synthetic_only": True},
    )
    green_observed = modeled(green)
    lab.check(
        "green", "Loss of one of three synthetic domains retains exactly quorum",
        green_observed == (green["surviving_members"], green["expected_quorum"],
                           green["expected_available"]),
        {"fixture": green["name"], "survivors": green_observed[0],
         "quorum": green_observed[1], "available": green_observed[2],
         "synthetic_only": True},
    )
    quorum = fixture["quorum_examples"]
    expected = [(3, 2, 1), (4, 3, 1), (5, 3, 2)]
    actual = [(row["members"], expected_quorum(row["members"]),
               row["members"] - expected_quorum(row["members"])) for row in quorum]
    lab.check(
        "positive", "Odd-member example uses resources efficiently for the same fault tolerance",
        actual == expected and all(
            (row["quorum"], row["tolerated_member_losses"]) == (need, tolerated)
            for row, (_, need, tolerated) in zip(quorum, expected)
        ),
        {"examples": [{"members": n, "quorum": q, "tolerated_losses": t}
                      for n, q, t in actual],
         "interpretation": "4 members tolerates 1 loss, the same as 3; odd is efficiency, not a standalone placement guarantee"},
    )


def assert_cluster_version(lab):
    version = json.loads(kubectl(lab, "version", "-o", "json").stdout)
    server = version.get("serverVersion", {}).get("gitVersion")
    if server != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1; observed {server!r}")


def etcdctl(lab, node, *args):
    ids = lab.command("docker", "exec", node, "crictl", "ps", "--name", "^etcd$", "-q",
                      timeout=10).stdout.splitlines()
    if len(ids) != 1 or not ids[0].isalnum():
        lab.block(f"Expected one running etcd container on {node}")
    return lab.command(
        "docker", "exec", node, "crictl", "exec", ids[0], "etcdctl",
        f"--endpoints={ETCD_ENDPOINT}", f"--cacert={ETCD_CERTS}/ca.crt",
        f"--cert={ETCD_CERTS}/healthcheck-client.crt", f"--key={ETCD_CERTS}/healthcheck-client.key",
        *args, "--write-out=json", timeout=18,
    ).stdout


def etcd_ready(lab, node):
    result = lab.command(
        "docker", "exec", node, "curl", "--fail", "--silent", "--show-error", "--max-time", "3",
        "--cacert", f"{ETCD_CERTS}/ca.crt", "--cert", f"{ETCD_CERTS}/healthcheck-client.crt",
        "--key", f"{ETCD_CERTS}/healthcheck-client.key", ETCD_ENDPOINT + "/readyz",
        timeout=8, allow_failure=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "ok"


def wait_for_ready_etcd_pods(lab, expected_nodes):
    deadline = time.monotonic() + 50
    while True:
        pods = json.loads(kubectl(lab, "-n", "kube-system", "get", "pods", "-l",
                                  "component=etcd", "-o", "json").stdout)["items"]
        by_node = {pod["spec"].get("nodeName"): pod for pod in pods}
        readiness = {node: False for node in sorted(expected_nodes)}
        if len(pods) == len(expected_nodes) and set(by_node) == expected_nodes:
            for node, pod in by_node.items():
                containers = pod["spec"].get("containers", [])
                if len(containers) != 1 or containers[0].get("image") != EXPECTED_ETCD_IMAGE:
                    lab.block(f"Unexpected etcd container image or count on {node}")
                status = pod.get("status", {})
                statuses = status.get("containerStatuses", [])
                readiness[node] = (status.get("phase") == "Running" and len(statuses) == 1
                                   and statuses[0].get("ready") is True)
        if all(readiness.values()) or time.monotonic() >= deadline:
            return readiness
        time.sleep(1)


def wait_for_ready_components(lab, expected_nodes):
    deadline = time.monotonic() + 90
    while True:
        replicas = {component: [] for component in COMPONENTS}
        pods = json.loads(kubectl(lab, "-n", "kube-system", "get", "pods",
                                  "-l", "tier=control-plane", "-o", "json").stdout)["items"]
        for pod in pods:
            meta, status = pod["metadata"], pod["status"]
            component = meta.get("labels", {}).get("component")
            node = pod["spec"]["nodeName"]
            ready = any(row.get("type") == "Ready" and row.get("status") == "True"
                        for row in status.get("conditions", []))
            if (component in replicas and node in expected_nodes and ready
                    and meta.get("annotations", {}).get("kubernetes.io/config.mirror")):
                replicas[component].append(node.removeprefix(lab.cluster + "-"))
        replicas = {component: sorted(nodes) for component, nodes in replicas.items()}
        matched = all(nodes == list(CONTROL_PLANES) for nodes in replicas.values())
        if matched or time.monotonic() >= deadline:
            return replicas, matched
        time.sleep(1)


def observe_topology(lab):
    nodes = json.loads(kubectl(lab, "get", "nodes", "-o", "json").stdout)["items"]
    by_name = {row["metadata"]["name"]: row for row in nodes}
    expected_nodes = {f"{lab.cluster}-{suffix}" for suffix in CONTROL_PLANES}
    actual_control_planes = {
        name for name, row in by_name.items()
        if "node-role.kubernetes.io/control-plane" in row["metadata"].get("labels", {})
    }
    if actual_control_planes != expected_nodes:
        lab.block(f"Unexpected control-plane node set: {sorted(actual_control_planes)}")
    node_conditions = {
        name: next((condition["status"] for condition in row["status"].get("conditions", [])
                    if condition.get("type") == "Ready"), None)
        for name, row in by_name.items() if name in expected_nodes
    }
    lab.check("green", "Exactly three configured control-plane nodes are Ready",
              set(node_conditions) == expected_nodes
              and all(status == "True" for status in node_conditions.values()),
              {"nodes": {name.removeprefix(lab.cluster + "-"): ready
                         for name, ready in sorted(node_conditions.items())}})

    replicas, matched = wait_for_ready_components(lab, expected_nodes)
    lab.check("green", "Each kubeadm control-plane component has one Ready static replica per node",
              matched, replicas)

    pod_readiness = wait_for_ready_etcd_pods(lab, expected_nodes)
    lab.check("green", "Each control-plane node has one Running and Ready etcd Pod",
              all(pod_readiness.values()),
              {"etcd_pods_ready_by_node": {
                  name.removeprefix(lab.cluster + "-"): ready
                  for name, ready in sorted(pod_readiness.items())},
               "image": EXPECTED_ETCD_IMAGE})

    member_sets = []
    for node in sorted(expected_nodes):
        members = json.loads(etcdctl(lab, node, "member", "list")).get("members", [])
        normalized = sorted((member.get("ID"), member.get("name"),
                             tuple(sorted(member.get("peerURLs", [])))) for member in members)
        if len(normalized) != 3 or any(not mid or not name or not urls for mid, name, urls in normalized):
            lab.block(f"Incomplete etcd membership data observed from {node}")
        member_sets.append(normalized)
    if any(members != member_sets[0] for members in member_sets[1:]):
        lab.block("The three etcd endpoints reported different member sets")
    actual_names = {member[1] for member in member_sets[0]}
    if actual_names != expected_nodes:
        lab.block(f"Unexpected etcd member names: {sorted(actual_names)}")
    unique_member_ids = len({member[0] for member in member_sets[0]}) == 3
    peer_urls = [url for _, _, urls in member_sets[0] for url in urls]
    unique_peer_urls = len(peer_urls) == len(set(peer_urls)) == 3

    endpoint_health = {}
    endpoint_readiness = {}
    for node in sorted(expected_nodes):
        rows = json.loads(etcdctl(lab, node, "endpoint", "health"))
        endpoint_health[node] = (len(rows) == 1 and rows[0].get("health") is True
                                 and not rows[0].get("error"))
        endpoint_readiness[node] = etcd_ready(lab, node)
    lab.check("green", "All three member endpoints report healthy and ready",
              unique_member_ids and unique_peer_urls
              and all(endpoint_health.values()) and all(endpoint_readiness.values()),
              {"member_names": sorted(name.removeprefix(lab.cluster + "-") for name in actual_names),
               "unique_member_ids": unique_member_ids, "unique_peer_urls": unique_peer_urls,
               "endpoint_health": [endpoint_health[name] for name in sorted(expected_nodes)],
               "endpoint_readyz": [endpoint_readiness[name] for name in sorted(expected_nodes)]})


def api_ready(lab):
    result = kubectl(lab, "get", "--raw=/readyz", timeout=8, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == "ok"


def write_read_probe(lab, phase):
    name = f"{CONFIGMAP}-{phase}"
    kubectl(lab, "-n", NAMESPACE, "create", "configmap", name,
            f"--from-literal={PROBE_KEY}={PROBE_VALUE}", timeout=25)
    observed = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "configmap", name,
                                  "-o", "json", timeout=30).stdout)
    return observed.get("data", {}).get(PROBE_KEY) == PROBE_VALUE


def run(lab):
    assert_cluster_version(lab)
    check_fixtures(lab)
    observe_topology(lab)

    if not api_ready(lab):
        lab.block("The API server /readyz endpoint was not ready before maintenance")
    if not write_read_probe(lab, "before"):
        lab.block("The synthetic ConfigMap read did not match the preceding write")
    lab.check("positive", "A bounded synthetic API ConfigMap write and read succeeds",
              True, {"namespace": NAMESPACE, "name": CONFIGMAP + "-before", "data_matches": True})

    target = f"{lab.cluster}-control-plane"
    inspection = json.loads(lab.command(
        "docker", "container", "inspect", target, "--format", "{{json .Config.Labels}}",
        timeout=10,
    ).stdout)
    # The exact cluster-specific name is generated by this runner and is in the
    # expected kind naming scheme. Never choose a host/container by discovery.
    if (not target.startswith("saf-lab-")
            or inspection.get("io.x-k8s.kind.cluster") != lab.cluster
            or inspection.get("io.x-k8s.kind.role") != "control-plane"):
        lab.block("Refusing to stop a container without the generated case-owned name")
    stopped = False
    try:
        stopped = True
        lab.command("docker", "stop", "--time", "10", target, timeout=20)
        running = lab.command("docker", "inspect", target, "--format", "{{.State.Running}}").stdout.strip()
        if running != "false":
            lab.block("The selected case-owned container is still running")
        deadline = time.monotonic() + 45
        last = "not observed"
        while time.monotonic() < deadline:
            last = "ready" if api_ready(lab) else "not ready"
            if last == "ready":
                break
            time.sleep(1)
        if last != "ready":
            lab.block("API /readyz did not recover while exactly one case-owned control plane was stopped")
        read_write_ok = write_read_probe(lab, "during")
        lab.check("green", "API read/write remains correct with one stopped control-plane node",
                  read_write_ok, {"stopped_node_role": "control-plane", "readyz": last,
                                  "synthetic_configmap_round_trip": read_write_ok})
    finally:
        if stopped:
            lab.command("docker", "start", target, timeout=30)

    # Wait for the restarted kubelet and member to rejoin before the runner deletes the cluster.
    deadline = time.monotonic() + 45
    restored = False
    while time.monotonic() < deadline:
        try:
            rows = json.loads(kubectl(lab, "get", "nodes", "-o", "json", timeout=20).stdout)["items"]
            state = {row["metadata"]["name"]: next(
                (condition["status"] for condition in row["status"].get("conditions", [])
                 if condition.get("type") == "Ready"), None) for row in rows}
            if (all(state.get(f"{lab.cluster}-{suffix}") == "True" for suffix in CONTROL_PLANES)
                    and etcd_ready(lab, target)):
                restored = True
                break
        except Exception:
            pass
        time.sleep(2)
    lab.check("positive", "The restarted control-plane node returns Ready", restored,
              {"node_role": "control-plane", "all_control_planes_ready": restored})
    observe_topology(lab)
    lab.check("positive", "An independent write/read also works after recovery",
              write_read_probe(lab, "after"), {"name": CONFIGMAP + "-after"})
