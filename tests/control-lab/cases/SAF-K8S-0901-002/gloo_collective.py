"""Bounded two-rank Gloo collective supplement for SAF-K8S-0901-002.

The CPU image is provided by the case runner. This module never builds or
downloads it. It reuses the published synthetic TokenReview aggregator and
fixed request vectors, then runs one actual two-Pod Gloo SUM reduction.
"""

import json
from ipaddress import ip_address, ip_network
from pathlib import Path
import time


NAMESPACE = "saf-0901-002"
PORT = 29500
ENROLLMENT_SERVICE = "collective-enrollment"
RANK0_SERVICE = "collective-rank-zero"
ROLE_LABEL = "saf-k8s.example/0901-002-collective-role"
IDENTITY_LABEL = "saf-k8s.example/0901-002-collective-identity"
GATE = "gloo-collective-start-gate"
GATE_ROLE = "gloo-collective-start-gate-reader"
EXPECTED = [0.03, -0.02, 0.02]
RANKS = {"worker-a": 0, "worker-b": 1}
REQUEST_KEYS = {"worker-a": "worker_a_valid", "worker-b": "worker_b_valid"}
EXPECTED_INPUTS = {
    "worker-a": [0.01, -0.02, 0.03],
    "worker-b": [0.02, 0.0, -0.01],
}


def _kubectl(lab, *args, **kwargs):
    return lab.kubectl(*args, timeout=kwargs.pop("timeout", 35), **kwargs)


def _apply(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace")
    args = ["-n", namespace] if namespace else []
    _kubectl(lab, *args, "apply", "-f", "-", payload=json.dumps(obj))


def _raw(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pod(name, identity, image, node_name):
    tolerations = []
    if node_name.endswith("-control-plane"):
        tolerations.append({"key": "node-role.kubernetes.io/control-plane",
                            "operator": "Exists", "effect": "NoSchedule"})
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {ROLE_LABEL: "rank-zero" if identity == "worker-a" else "rank-one",
                                IDENTITY_LABEL: identity}},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": identity,
            "automountServiceAccountToken": False,
            "nodeSelector": {"kubernetes.io/hostname": node_name},
            "tolerations": tolerations,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "collective", "image": image, "imagePullPolicy": "Never",
                "command": ["python3", "/case/gloo_worker.py"],
                "env": [
                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                    {"name": "HOME", "value": "/tmp"},
                    {"name": "TMPDIR", "value": "/tmp"},
                    {"name": "OMP_NUM_THREADS", "value": "1"},
                    {"name": "MKL_NUM_THREADS", "value": "1"},
                    {"name": "FIXTURE_WORKER_ID", "value": identity},
                    {"name": "ENROLLMENT_URL", "value":
                     f"http://{ENROLLMENT_SERVICE}.{NAMESPACE}.svc.cluster.local:8080"},
                    {"name": "RANK_ZERO_URL", "value":
                     f"tcp://{RANK0_SERVICE}.{NAMESPACE}.svc.cluster.local:{PORT}"},
                ],
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "500m", "memory": "1Gi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [
                    {"name": "code", "mountPath": "/case", "readOnly": True},
                    {"name": "identity", "mountPath": "/run/fixture-identity", "readOnly": True},
                    {"name": "tmp", "mountPath": "/tmp"},
                ],
            }],
            "volumes": [
                {"name": "code", "configMap": {"name": "gloo-worker-code"}},
                {"name": "identity", "projected": {"sources": [
                    {"serviceAccountToken": {"audience": "saf-fixture-0901-002",
                                              "expirationSeconds": 600, "path": "token"}},
                    {"serviceAccountToken": {"expirationSeconds": 600, "path": "api-token"}},
                    {"configMap": {"name": "kube-root-ca.crt",
                                    "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
                ]}},
                {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
            ],
        },
    }


def _service(name, selector):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "spec": {"type": "ClusterIP", "selector": selector,
                     "ports": [{"name": "store", "protocol": "TCP",
                                "port": PORT, "targetPort": PORT}]}}


def _gate_rbac(lab):
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": GATE, "namespace": NAMESPACE},
                 "data": {"start": "hold"}})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": GATE_ROLE, "namespace": NAMESPACE},
                 "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                            "resourceNames": [GATE], "verbs": ["get"]}]})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                 "metadata": {"name": GATE_ROLE, "namespace": NAMESPACE},
                 "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}
                              for name in ("worker-a", "worker-b")],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": GATE_ROLE}})


def _wait_enrolled(lab, timeout=30):
    deadline = time.monotonic() + timeout
    latest = []
    while time.monotonic() < deadline:
        output = _kubectl(lab, "-n", NAMESPACE, "logs", "pod/gloo-enrollment",
                          timeout=15, allow_failure=True)
        latest = [json.loads(line) for line in output.stdout.splitlines() if line.strip()]
        enrolled = {row.get("worker_id") for row in latest
                    if row.get("outcome") == "enrolled_for_collective"
                    and row.get("round_id") == "round-7"
                    and row.get("rank") in (0, 1)}
        if enrolled == set(RANKS):
            return latest
        time.sleep(0.2)
    lab.block("Both fixed Gloo workers did not reach the authenticated pre-collective gate")
    return latest


def _node_ip(lab, node_name):
    nodes = json.loads(_kubectl(lab, "get", "nodes", "-o", "json").stdout)["items"]
    matches = [item for item in nodes if item.get("metadata", {}).get("name") == node_name]
    if len(matches) != 1:
        lab.block("A fixed Gloo Pod is not bound to exactly one expected node")
    addresses = [row.get("address") for row in matches[0].get("status", {}).get("addresses", [])
                 if row.get("type") == "InternalIP" and ":" not in row.get("address", "")]
    if len(addresses) != 1:
        lab.block("A fixed Gloo node has no unique IPv4 internal address")
    return addresses[0]


def _pair_counter(lab, node_container, table, source_ip, destination_ip):
    device = "cilium_wg0"
    links = json.loads(lab.command("docker", "exec", node_container, "ip", "-j", "-details",
                                   "link", "show", "dev", device).stdout)
    if len(links) != 1 or links[0].get("linkinfo", {}).get("info_kind") != "wireguard":
        lab.block("The fixed Gloo node has no Cilium WireGuard ingress interface")
    source, destination = ip_address(source_ip), ip_address(destination_ip)
    if source.version != 4 or destination.version != 4:
        lab.block("The fixed Gloo pair-flow counter requires the reviewed IPv4 profile")
    rules = f"""
table netdev {table} {{
  counter matched {{}}
  chain fixture {{
    type filter hook ingress device \"{device}\" priority 0; policy accept;
    ip saddr {source} ip daddr {destination} meta l4proto tcp counter name \"matched\"
  }}
}}
"""
    lab.command("docker", "exec", "-i", node_container, "nft", "-f", "-", payload=rules)

    def read():
        output = lab.command("docker", "exec", node_container, "nft", "-j", "list", "counter",
                             "netdev", table, "matched")
        row = next((item.get("counter") for item in json.loads(output.stdout).get("nftables", [])
                    if "counter" in item), None)
        if (not row or not isinstance(row.get("packets"), int)
                or not isinstance(row.get("bytes"), int)):
            lab.block("The exact Gloo inner-flow counter did not return bounded numeric statistics")
        return {"packets": row["packets"], "bytes": row["bytes"]}
    return read


def _wireguard_helper(lab):
    import importlib.util
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0504-002" / "cilium" / "cilium_case.py"
    spec = importlib.util.spec_from_file_location("saf_0901_002_wireguard_observer", path)
    if spec is None or spec.loader is None:
        lab.block("The published Cilium WireGuard observation helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_gate(lab):
    _kubectl(lab, "-n", NAMESPACE, "patch", "configmap", GATE, "--type=merge",
             "-p", json.dumps({"data": {"start": "go"}}))


def _get_pod(lab, name):
    return json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)


def _wait_running(lab, name, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _get_pod(lab, name)
        status = last.get("status", {})
        if status.get("phase") == "Running":
            containers = status.get("containerStatuses", [])
            if len(containers) == 1 and containers[0].get("ready") is True:
                return last
            if len(containers) == 1 and containers[0].get("state", {}).get("running"):
                return last
        # Rank one can finish before the following poll observes Running;
        # Succeeded still proves that the owned Pod started normally.
        if status.get("phase") == "Succeeded":
            return last
        if status.get("phase") == "Failed":
            break
        time.sleep(0.25)
    lab.block(f"The owned collective Pod {name} did not start within its bound")
    return last


def _wait_rank_zero_endpoint(lab, pod_ip, timeout=30):
    deadline = time.monotonic() + timeout
    latest = {"items": []}
    while time.monotonic() < deadline:
        latest = json.loads(_kubectl(
            lab, "-n", NAMESPACE, "get", "endpointslices", "-l",
            f"kubernetes.io/service-name={RANK0_SERVICE}", "-o", "json").stdout)
        addresses = [address for item in latest.get("items", [])
                     for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready")
                     for address in endpoint.get("addresses", [])]
        if addresses == [pod_ip]:
            return latest, addresses
        time.sleep(0.25)
    return latest, []


def _worker_result(lab, name):
    pod = _get_pod(lab, name)
    if pod.get("status", {}).get("phase") != "Succeeded":
        lab.block(f"The owned collective Pod {name} did not complete successfully")
    result = _kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{name}", timeout=20).stdout.strip()
    try:
        rows = [json.loads(line.removeprefix("SAF_GLOO_RESULT "))
                for line in result.splitlines() if line.startswith("SAF_GLOO_RESULT ")]
    except json.JSONDecodeError:
        lab.block(f"The owned collective Pod {name} emitted no bounded result record")
    if len(rows) != 1:
        lab.block(f"The owned collective Pod {name} emitted an unexpected result count")
    return rows[0]


def _wait_succeeded(lab, names, timeout=90):
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        latest = {name: _get_pod(lab, name) for name in names}
        phases = {name: pod.get("status", {}).get("phase")
                  for name, pod in latest.items()}
        if all(phase == "Succeeded" for phase in phases.values()):
            return latest
        if any(phase == "Failed" for phase in phases.values()):
            break
        time.sleep(0.25)
    lab.block("The bounded two-rank collective did not complete successfully")
    return latest


def _cleanup(lab):
    for kind, names in (("pod", ("gloo-worker-a", "gloo-worker-b", "gloo-enrollment")),
                        ("service", (RANK0_SERVICE, ENROLLMENT_SERVICE)),
                        ("configmap", ("gloo-server-code", "gloo-worker-code", GATE)),
                        ("rolebinding", (GATE_ROLE,)), ("role", (GATE_ROLE,))):
        for name in names:
            _kubectl(lab, "-n", NAMESPACE, "delete", kind, name,
                     "--ignore-not-found=true", "--wait=true", allow_failure=True, timeout=35)


def run(lab, case_dir, image, provenance):
    """Run two authenticated workers through the existing assignment gate and Gloo SUM.

    `image` is the short-lived, locally built and imported runtime supplied by
    the parent runner. `provenance` is the wheel-lock summary; it contains only
    architecture and package hashes, never package bytes or credentials.
    """
    fixture = Path(case_dir) / "fixtures"
    aggregator = (fixture / "aggregator.py").read_text(encoding="utf-8")
    server = (fixture / "collective_aggregator.py").read_text(encoding="utf-8")
    worker = (fixture / "gloo_worker.py").read_text(encoding="utf-8")
    requests = (fixture / "requests.json").read_text(encoding="utf-8")
    request_map = json.loads(requests)

    nodes = json.loads(_kubectl(lab, "get", "nodes", "-o", "json").stdout)["items"]
    control_nodes = [node for node in nodes
                     if "node-role.kubernetes.io/control-plane" in node.get("metadata", {}).get("labels", {})]
    worker_nodes = [node for node in nodes if node not in control_nodes]
    if len(nodes) != 2 or len(control_nodes) != 1 or len(worker_nodes) != 1:
        lab.block("The published two-node profile did not produce one control-plane and one worker node")
    node_for_worker = {"worker-a": control_nodes[0]["metadata"]["name"],
                       "worker-b": worker_nodes[0]["metadata"]["name"]}
    kind_nodes = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if kind_nodes != {node_for_worker["worker-a"], node_for_worker["worker-b"]}:
        lab.block("Kubernetes node names do not exactly match the owned Kind node containers")

    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "gloo-server-code", "namespace": NAMESPACE},
                 "data": {"aggregator.py": aggregator,
                          "collective_aggregator.py": server}})
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "gloo-worker-code", "namespace": NAMESPACE},
                 "data": {"gloo_worker.py": worker, "requests.json": requests}})
    _gate_rbac(lab)

    # Remove the earlier client Pods after all 17 original checks. The same two
    # service accounts now identify exactly one live worker Pod apiece.
    for name in ("worker-a", "worker-b", "observer"):
        _kubectl(lab, "-n", NAMESPACE, "delete", "pod", name,
                 "--wait=true", timeout=35)

    # This separate mock reuses the exact published TokenReview and contribution
    # handler. Its only addition is a rank assignment returned after that same
    # TokenReview has authenticated an already-enrolled worker.
    _apply(lab, {"apiVersion": "v1", "kind": "Service",
                 "metadata": {"name": ENROLLMENT_SERVICE, "namespace": NAMESPACE},
                 "spec": {"type": "ClusterIP", "selector": {ROLE_LABEL: "enrollment"},
                          "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    _apply(lab, {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "gloo-enrollment", "namespace": NAMESPACE,
                              "labels": {ROLE_LABEL: "enrollment"}},
                 "spec": {"restartPolicy": "Always", "serviceAccountName": "aggregation",
                          "automountServiceAccountToken": True,
                          "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                              "seccompProfile": {"type": "RuntimeDefault"}},
                          "containers": [{"name": "server", "image":
                                          "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                                          "imagePullPolicy": "IfNotPresent",
                                          "command": ["python3", "/case/collective_aggregator.py"],
                                          "env": [{"name": "ENFORCEMENT_MODE", "value": "enforce"}],
                                          "ports": [{"containerPort": 8080}],
                                          "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080},
                                                             "periodSeconds": 1, "timeoutSeconds": 2},
                                          "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                        "limits": {"cpu": "100m", "memory": "64Mi"}},
                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                              "readOnlyRootFilesystem": True,
                                                              "capabilities": {"drop": ["ALL"]}},
                                          "volumeMounts": [{"name": "code", "mountPath": "/case",
                                                            "readOnly": True}]}],
                          "volumes": [{"name": "code", "configMap": {"name": "gloo-server-code"}}]}})
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready",
             "pod/gloo-enrollment", "--timeout=60s", timeout=70)
    _apply(lab, _service(RANK0_SERVICE, {IDENTITY_LABEL: "worker-a"}))

    worker_names = ("gloo-worker-a", "gloo-worker-b")
    try:
        rank_zero = _pod("gloo-worker-a", "worker-a", image, node_for_worker["worker-a"])
        _apply(lab, rank_zero)
        rank_zero_live = _wait_running(lab, "gloo-worker-a")
        rank_zero_slices, rank_zero_addresses = _wait_rank_zero_endpoint(
            lab, rank_zero_live.get("status", {}).get("podIP"))
        if rank_zero_addresses != [rank_zero_live.get("status", {}).get("podIP")]:
            lab.block("The rank-zero Service does not select exactly the owned rank-zero Pod")

        rank_one = _pod("gloo-worker-b", "worker-b", image, node_for_worker["worker-b"])
        _apply(lab, rank_one)
        rank_one_live = _wait_running(lab, "gloo-worker-b")

        # Both processes are authenticated and blocked before Gloo can open a
        # peer socket. Bind exact Pod IPs to passive counters first.
        enrollment_ready = _wait_enrolled(lab)
        deadline = time.monotonic() + 20
        ready = {}
        while time.monotonic() < deadline:
            ready = {}
            for identity, pod_name in (("worker-a", "gloo-worker-a"), ("worker-b", "gloo-worker-b")):
                log = _kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{pod_name}",
                               timeout=10, allow_failure=True).stdout
                rows = []
                for line in log.splitlines():
                    if line.startswith("SAF_GLOO_READY "):
                        try:
                            rows.append(json.loads(line.removeprefix("SAF_GLOO_READY ")))
                        except json.JSONDecodeError:
                            lab.block("A worker emitted malformed fixed readiness evidence")
                ready[identity] = any(row == {"worker_id": identity, "rank": RANKS[identity],
                                             "enrolled": True} for row in rows)
            if all(ready.values()):
                break
            time.sleep(0.2)
        if not all(ready.values()):
            lab.block("Both enrolled workers did not reach the pre-collective barrier")

        gate_permissions = {}
        for identity in RANKS:
            as_user = f"system:serviceaccount:{NAMESPACE}:{identity}"
            exact_get = _kubectl(lab, "auth", "can-i", "get", f"configmaps/{GATE}",
                                 "-n", NAMESPACE, "--as", as_user, allow_failure=True).stdout.strip()
            list_get = _kubectl(lab, "auth", "can-i", "list", "configmaps",
                                "-n", NAMESPACE, "--as", as_user, allow_failure=True).stdout.strip()
            other_get = _kubectl(lab, "auth", "can-i", "get", "configmaps/other-fixture-state",
                                 "-n", NAMESPACE, "--as", as_user, allow_failure=True).stdout.strip()
            gate_permissions[identity] = {"exact_get": exact_get == "yes",
                                          "list_denied": list_get == "no",
                                          "other_name_denied": other_get == "no"}
        gate_permissions_ok = all(all(values.values()) for values in gate_permissions.values())

        worker_a_ip = rank_zero_live.get("status", {}).get("podIP")
        worker_b_ip = rank_one_live.get("status", {}).get("podIP")
        if not worker_a_ip or not worker_b_ip or worker_a_ip == worker_b_ip:
            lab.block("The two fixed Gloo worker Pods lack distinct live Pod IPs")
        wireguard_a_to_b = _pair_counter(lab, node_for_worker["worker-a"],
                                         "safgloo_a_to_b", worker_b_ip, worker_a_ip)
        wireguard_b_to_a = _pair_counter(lab, node_for_worker["worker-b"],
                                         "safgloo_b_to_a", worker_a_ip, worker_b_ip)
        counters_before = {"worker-a-receives-worker-b": wireguard_a_to_b(),
                           "worker-b-receives-worker-a": wireguard_b_to_a()}
        if any(value != {"packets": 0, "bytes": 0} for value in counters_before.values()):
            lab.block("The exact Gloo Pod-pair WireGuard counters were not empty before release")

        profile = _wireguard_helper(lab)
        node_ip_a = _node_ip(lab, node_for_worker["worker-a"])
        node_ip_b = _node_ip(lab, node_for_worker["worker-b"])
        state_a_before = profile.wireguard_state(lab, node_for_worker["worker-a"])
        state_b_before = profile.wireguard_state(lab, node_for_worker["worker-b"])
        peer_a_before = profile.wg_peer_for_path(state_a_before, worker_b_ip, node_ip_b)
        peer_b_before = profile.wg_peer_for_path(state_b_before, worker_a_ip, node_ip_a)
        peer_coverage_before = (len(peer_a_before) == 1 and len(peer_b_before) == 1
                                and any(ip_address(worker_b_ip) in ip_network(cidr, strict=False)
                                        for cidr in peer_a_before[0].get("allowed_ips", []))
                                and any(ip_address(worker_a_ip) in ip_network(cidr, strict=False)
                                        for cidr in peer_b_before[0].get("allowed_ips", [])))
        if not peer_coverage_before:
            lab.block("The pre-collective WireGuard peers do not cover the exact remote Gloo Pod IPs")

        _release_gate(lab)
        succeeded_pods = _wait_succeeded(lab, worker_names)
        counters_after = {"worker-a-receives-worker-b": wireguard_a_to_b(),
                          "worker-b-receives-worker-a": wireguard_b_to_a()}
        flow_ok = all(counters_after[key]["packets"] > counters_before[key]["packets"]
                      and counters_after[key]["bytes"] > counters_before[key]["bytes"]
                      for key in counters_before)
        state_a_after = profile.wireguard_state(lab, node_for_worker["worker-a"])
        state_b_after = profile.wireguard_state(lab, node_for_worker["worker-b"])
        peer_a = profile.wg_peer_for_path(state_a_after, worker_b_ip, node_ip_b)
        peer_b = profile.wg_peer_for_path(state_b_after, worker_a_ip, node_ip_a)
        peer_coverage = (len(peer_a) == 1 and len(peer_b) == 1
                         and any(ip_address(worker_b_ip) in ip_network(cidr, strict=False)
                                 for cidr in peer_a[0].get("allowed_ips", []))
                         and any(ip_address(worker_a_ip) in ip_network(cidr, strict=False)
                                 for cidr in peer_b[0].get("allowed_ips", []))
                         and profile.recent_handshake(peer_a[0]) and profile.recent_handshake(peer_b[0]))
        interfaces_ok = (any(row.get("name") == "cilium_wg0" for row in state_a_after.get("interfaces", []))
                         and any(row.get("name") == "cilium_wg0" for row in state_b_after.get("interfaces", [])))

        results = {name: _worker_result(lab, pod_name)
                   for name, pod_name in (("worker-a", "gloo-worker-a"),
                                          ("worker-b", "gloo-worker-b"))}
        server_log = _kubectl(lab, "-n", NAMESPACE, "logs", "pod/gloo-enrollment").stdout
        server_events = [json.loads(line) for line in server_log.splitlines() if line.strip()]
        pod_by_worker = {"worker-a": succeeded_pods["gloo-worker-a"],
                         "worker-b": succeeded_pods["gloo-worker-b"]}
        pod_objects = {name: {
            "name": pod.get("metadata", {}).get("name"),
            "uid": pod.get("metadata", {}).get("uid"),
            "service_account": pod.get("spec", {}).get("serviceAccountName"),
            "phase": pod.get("status", {}).get("phase"),
            "pod_ip": pod.get("status", {}).get("podIP"),
            "image": pod.get("spec", {}).get("containers", [{}])[0].get("image"),
            "image_id": pod.get("status", {}).get("containerStatuses", [{}])[0].get("imageID"),
            "node_name": pod.get("spec", {}).get("nodeName"),
            "node_role": "control-plane" if pod.get("spec", {}).get("nodeName") == node_for_worker["worker-a"] else "worker",
            "role_label": pod.get("metadata", {}).get("labels", {}).get(ROLE_LABEL),
            "identity_label": pod.get("metadata", {}).get("labels", {}).get(IDENTITY_LABEL),
        } for name, pod in pod_by_worker.items()}
        exact_images = all(pod_objects[name].get("image") == image for name in RANKS)
        exact_cross_node_placement = (pod_objects["worker-a"].get("node_name") != pod_objects["worker-b"].get("node_name")
                                      and pod_objects["worker-a"].get("node_name") == node_for_worker["worker-a"]
                                      and pod_objects["worker-b"].get("node_name") == node_for_worker["worker-b"])
        exact_results = all(
            results[name] == {"worker_id": name, "rank": RANKS[name],
                              "round_id": "round-7", "accepted_http_status": 200,
                              "accepted_response": {"status": "accepted"},
                              "torch_version": "2.15.0+cpu", "gloo_available": True,
                              "backend": "gloo", "device": "cpu", "world_size": 2,
                              "input": EXPECTED_INPUTS[name], "operation": "sum",
                              "result": EXPECTED}
            for name in RANKS)
        expected_events = [
            {"outcome": "accepted", "worker_id": "worker-a",
             "request": request_map["worker_a_valid"]},
            {"outcome": "accepted", "worker_id": "worker-b",
             "request": request_map["worker_b_valid"]},
            {"outcome": "enrolled_for_collective", "worker_id": "worker-a",
             "round_id": "round-7", "rank": 0},
            {"outcome": "enrolled_for_collective", "worker_id": "worker-b",
             "round_id": "round-7", "rank": 1},
        ]
        events_observed = sorted(expected_events,
                                 key=lambda row: (row["outcome"], row["worker_id"]))
        projected_events = []
        for row in server_events:
            if row.get("outcome") == "enrolled_for_collective":
                projected_events.append({key: row.get(key)
                                         for key in ("outcome", "worker_id", "round_id", "rank")})
            elif row.get("outcome") == {"status": "accepted"}:
                projected_events.append({"outcome": "accepted",
                                         "worker_id": row.get("authenticated_identity"),
                                         "request": row.get("request")})
        actual_events = sorted(projected_events,
                               key=lambda row: (row["outcome"], row["worker_id"]))
        enrollment_ok = len(server_events) == len(expected_events) and actual_events == events_observed
        raw = {"scope": "Two legitimate synthetic worker Pods each submit their existing fixed in-range vector to the reused TokenReview/schema/assignment handler, receive a rank only after authenticated enrollment, and perform one real CPU Gloo SUM all-reduce. They are pinned to different nodes in the exact two-node Cilium WireGuard profile. Exact inner Pod-IP-pair TCP counters are installed at zero before the controlled collective gate is released. This proves only case-owned cross-node Cilium WireGuard path coverage; it does not prove Gloo-native TLS or application peer authentication.",
               "runtime_image": image, "runtime_provenance": provenance,
               "expected_torch_version": "2.15.0+cpu", "expected_backend": "gloo",
               "request_keys": REQUEST_KEYS, "expected_rank_mapping": RANKS,
               "expected_inputs": EXPECTED_INPUTS, "expected_sum": EXPECTED,
               "actual_worker_results": results, "server_events": server_events,
               "expected_projected_events": events_observed,
               "observed_projected_events": actual_events, "pods": pod_objects,
               "rank_zero_endpoint_slices": rank_zero_slices,
               "rank_zero_endpoint_addresses": rank_zero_addresses,
               "nodes": {"worker-a": {"node_name": node_for_worker["worker-a"], "internal_ip": node_ip_a},
                         "worker-b": {"node_name": node_for_worker["worker-b"], "internal_ip": node_ip_b}},
               "pre_collective_enrollment_events": enrollment_ready,
               "start_gate_permissions": gate_permissions,
               "wireguard_counters_before": counters_before,
               "wireguard_counters_after": counters_after,
               "wireguard_peer_a": [{"allowed_ips": peer.get("allowed_ips"),
                                     "last_handshake_time": peer.get("last_handshake_time"),
                                     "both_directions": peer.get("both_directions")} for peer in peer_a],
               "wireguard_peer_b": [{"allowed_ips": peer.get("allowed_ips"),
                                     "last_handshake_time": peer.get("last_handshake_time"),
                                     "both_directions": peer.get("both_directions")} for peer in peer_b],
               "wireguard_interface_on_both_nodes": interfaces_ok,
               "wireguard_peer_coverage_before_collective": peer_coverage_before,
               "counter_start_at_zero": all(value == {"packets": 0, "bytes": 0}
                                              for value in counters_before.values()),
               "wireguard_pair_counters_increased": flow_ok,
               "cross_node_worker_placement": exact_cross_node_placement,
               "enrollment_assignments_match": enrollment_ok,
               "worker_outputs_match": exact_results,
               "runtime_image_matches": exact_images,
               "tokens_or_credentials_logged": False,
               "external_targets_accessed": False,
               "model_training_performed": False}
        _raw(lab.evidence / "gloo-two-rank-raw.json", raw)
        lab.check("positive",
                  "Two distinct TokenReview-authenticated enrolled worker Pods receive their fixed ranks and run the pinned CPU Gloo runtime",
                  enrollment_ok and exact_images and all(pod_objects[name].get("phase") == "Succeeded"
                                                           for name in RANKS),
                  {"distinct_enrolled_identities_and_ranks": enrollment_ok,
                   "pinned_runtime_image_on_both_workers": exact_images,
                   "both_owned_rank_pods_completed": all(
                       pod_objects[name].get("phase") == "Succeeded" for name in RANKS),
                   "raw_evidence": "gloo-two-rank-raw.json"})
        lab.check("positive",
                  "The two-rank CPU Gloo all-reduce returns the exact fixed-vector sum to both enrolled workers",
                  exact_results,
                  {"both_worker_results_equal_expected_sum": exact_results,
                   "backend": "gloo", "device": "cpu", "world_size": 2,
                   "vector_length": 3, "collectives_per_worker": 1,
                   "expected_sum": EXPECTED,
                   "raw_evidence": "gloo-two-rank-raw.json"})
        lab.check("positive",
                  "The fixed Gloo collective traverses the reciprocal Cilium WireGuard path between the exact enrolled cross-node Pod pair",
                  exact_cross_node_placement and gate_permissions_ok and peer_coverage
                  and interfaces_ok and flow_ok and exact_images and enrollment_ok,
                  {"exact_enrolled_pods_on_distinct_nodes": exact_cross_node_placement and enrollment_ok,
                   "rank_zero_service_endpoint_matches_owned_pod": rank_zero_addresses == [worker_a_ip],
                   "reciprocal_wireguard_peer_coverage_and_recent_handshakes": peer_coverage,
                   "exact_pair_flow_counters_started_at_zero_and_increased": flow_ok,
                   "wireguard_peers_cover_exact_pods_before_release": peer_coverage_before,
                   "worker_api_gate_is_get_only_for_exact_object": gate_permissions_ok,
                   "raw_evidence": "gloo-two-rank-raw.json"})

        # Remove the temporary passive nft tables after reading their counters.
        for node_name, table in ((node_for_worker["worker-a"], "safgloo_a_to_b"),
                                 (node_for_worker["worker-b"], "safgloo_b_to_a")):
            lab.command("docker", "exec", node_name, "nft", "delete", "table", "netdev", table,
                        allow_failure=True)
    finally:
        _cleanup(lab)
