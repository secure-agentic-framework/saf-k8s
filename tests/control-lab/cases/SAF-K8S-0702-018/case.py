"""Demonstrate API and ordinary pod-network boundaries for two tenants."""
import json
import time

from fixtures import container, pod


TENANTS = ("saf-0702-018-a", "saf-0702-018-b")
APP = "saf-k8s.example/0702-018"
PORT = 8080
MARKERS = {TENANTS[0]: "tenant-a-fixed-listener", TENANTS[1]: "tenant-b-fixed-listener"}
RECORD = "tenant-record"
SCOPE = (
    "Two case-owned namespaces on kind v1.36.1 with the image-pinned stock kindnet: "
    "an API GET limited by native Role/RoleBinding to one ConfigMap name in one namespace, "
    "plus same-node IPv4 TCP Pod connectivity to fixed port 8080 before and after ingress/egress "
    "NetworkPolicies. No API authentication, tenant ability to administer its namespace, "
    "hostNetwork/node path, other protocols, addresses, CNIs, shared-node isolation, or hostile "
    "tenant behavior is established."
)


def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    if namespace:
        lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))
    else:
        lab.kubectl("create", "-f", "-", payload=json.dumps(resource))


def read_identity(namespace):
    return f"system:serviceaccount:{namespace}:boundary-reader"


def read_record(lab, acting_namespace, target_namespace, expected_allowed,
                expected_marker=None, record=RECORD):
    identity = read_identity(acting_namespace)
    result = lab.kubectl(
        "--as", identity,
        "--as-group=system:serviceaccounts",
        f"--as-group=system:serviceaccounts:{acting_namespace}",
        "--as-group=system:authenticated",
        "-n", target_namespace, "get", "configmap", record, "-o", "json",
        allow_failure=True,
    )
    if expected_allowed:
        allowed = result.returncode == 0
        marker = None
        if allowed:
            try:
                marker = json.loads(result.stdout)["data"]["marker"]
            except (KeyError, json.JSONDecodeError):
                lab.block("Permitted ConfigMap read returned malformed or unexpected data")
        lab.check(
            "positive", f"{acting_namespace} reads {target_namespace}/{record}",
            allowed and marker == expected_marker,
            {"namespace": target_namespace, "resource": record, "marker": marker,
             "returncode": result.returncode},
        )
        return
    denied = result.returncode != 0 and "forbidden" in result.stderr.lower()
    lab.check(
        "green", f"{acting_namespace} cannot read {target_namespace}/{record}", denied,
        {"namespace": target_namespace, "resource": record, "forbidden": denied,
         "returncode": result.returncode},
    )


def listener(lab, namespace):
    name = "tenant-listener"
    command = [
        "sh", "-ec",
        f"printf %s {MARKERS[namespace]} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
    ]
    workload = pod(name, [container("listener", command=command)])
    workload["metadata"].update(namespace=namespace, labels={APP: "listener"})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    if not current.get("status", {}).get("podIP"):
        lab.block("Listener has no Pod IP")
    return current["status"]["podIP"]


def client(lab, namespace):
    name = "tenant-client"
    workload = pod(name, [container("client")])
    workload["metadata"].update(namespace=namespace, labels={APP: "client"})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)


def connectivity(lab, source_namespace, destination_ip, expected_marker):
    result = lab.kubectl(
        "-n", source_namespace, "exec", "pod/tenant-client", "--", "wget", "-q", "-T", "2",
        "-O", "-", f"http://{destination_ip}:{PORT}/", allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != expected_marker:
            lab.block("Fixed-listener probe returned an unexpected marker")
        return True
    combined = (result.stdout + result.stderr).lower()
    if any(reason in combined for reason in (
            "timed out", "connection refused", "no route to host", "network is unreachable")):
        return False
    lab.block("Fixed-listener probe failed without a recognized network outcome")


def expect_connectivity(lab, phase, source_namespace, destination_ip, marker, allowed):
    deadline = time.monotonic() + 30
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        observed = connectivity(lab, source_namespace, destination_ip, marker)
        consecutive = consecutive + 1 if observed == allowed else 0
        if consecutive >= 2:
            break
        time.sleep(0.5)
    lab.check(
        phase,
        f"{source_namespace} {'reaches' if allowed else 'cannot reach'} the fixed listener",
        consecutive >= 2,
        {"expected_reachable": allowed, "observed_reachable": observed,
         "two_consecutive_observations": consecutive >= 2, "port": PORT},
    )


def add_api_read_binding(lab, namespace):
    create(lab, {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": "boundary-reader", "namespace": namespace},
        "automountServiceAccountToken": False,
    })
    create(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "read-one-record", "namespace": namespace},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [RECORD], "verbs": ["get"]}],
    })
    create(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "boundary-reader", "namespace": namespace},
        "subjects": [{"kind": "ServiceAccount", "name": "boundary-reader",
                      "namespace": namespace, "apiGroup": ""}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "read-one-record"},
    })


def add_network_policy(lab, namespace):
    create(lab, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "tenant-boundary", "namespace": namespace},
        "spec": {
            "podSelector": {}, "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {APP: "client"}}}],
                         "ports": [{"protocol": "TCP", "port": PORT}]}],
            "egress": [{"to": [{"podSelector": {"matchLabels": {APP: "listener"}}}],
                        "ports": [{"protocol": "TCP", "port": PORT}]}],
        },
    })


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    runtimes = [node["status"]["nodeInfo"]["containerRuntimeVersion"] for node in nodes]
    net = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item["image"] for item in net["spec"]["template"]["spec"]["containers"]]
    lab.check("green", "Pinned kind node runtime and stock kindnet are present",
              len(nodes) == 1 and all(runtime.startswith("containerd://") for runtime in runtimes)
              and any("kindnetd" in image for image in images),
              {"node_runtime_versions": runtimes, "kindnet_images": images,
               "node_count": len(nodes)})
    for namespace in TENANTS:
        lab.kubectl("create", "namespace", namespace)
        for name in (RECORD, "other-record"):
            create(lab, {
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": namespace},
                "data": {"marker": f"{namespace}-{name}-synthetic"},
            })

    # The baseline proves the reader identity has no effective access before its RoleBinding.
    read_record(lab, TENANTS[0], TENANTS[0], False)
    read_record(lab, TENANTS[0], TENANTS[1], False)
    for namespace in TENANTS:
        add_api_read_binding(lab, namespace)
    read_record(lab, TENANTS[0], TENANTS[0], True, f"{TENANTS[0]}-{RECORD}-synthetic")
    read_record(lab, TENANTS[1], TENANTS[1], True, f"{TENANTS[1]}-{RECORD}-synthetic")
    read_record(lab, TENANTS[0], TENANTS[0], False, record="other-record")
    read_record(lab, TENANTS[0], TENANTS[1], False)
    read_record(lab, TENANTS[1], TENANTS[0], False)

    addresses = {}
    for namespace in TENANTS:
        addresses[namespace] = listener(lab, namespace)
        client(lab, namespace)

    for source, target in (TENANTS, TENANTS[::-1]):
        expect_connectivity(lab, "red", source, addresses[target], MARKERS[target], True)
    for namespace in TENANTS:
        add_network_policy(lab, namespace)
    for source, target in (TENANTS, TENANTS[::-1]):
        expect_connectivity(lab, "green", source, addresses[target], MARKERS[target], False)
        expect_connectivity(lab, "positive", source, addresses[source], MARKERS[source], True)
    for namespace in TENANTS:
        lab.kubectl("-n", namespace, "delete", "networkpolicy", "tenant-boundary")
    for source, target in (TENANTS, TENANTS[::-1]):
        expect_connectivity(lab, "positive", source, addresses[target], MARKERS[target], True)
