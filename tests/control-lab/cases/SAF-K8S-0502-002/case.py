"""Verify Cilium WireGuard encryption for one synthetic cross-node pod path.

The harness owns the disposable Kind cluster lifecycle. This case installs the
pinned CNI, creates two case-owned marker endpoints, and records only scoped
status and WireGuard transfer counters. It does not capture packets.
"""
import hashlib
import json
from ipaddress import ip_address, ip_network
import subprocess
from pathlib import Path
import re
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KUBERNETES_VERSION = "v1.36.1"
KIND_VERSION = "v0.32.0"
CILIUM_VERSION = "1.20.5"
INSTALLS_CNI = True
CHART_SOURCE = "oci://quay.io/cilium/charts/cilium"
CHART_HASH = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
CILIUM_IMAGE = (
    "quay.io/cilium/cilium:v1.20.5@sha256:"
    "aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
)
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PORT = 18080
BODY_BYTES = 65536
NAMESPACE = "saf-0502-002"
ENDPOINTS = {
    "source": {"name": "synthetic-source", "marker": "saf-0502-002-source-fixed-marker"},
    "destination": {"name": "synthetic-destination", "marker": "saf-0502-002-destination-fixed-marker"},
}
WIREGUARD_INTERFACE = "cilium_wg0"
SCOPE = (
    "One fresh local Kind v0.32.0 cluster with exactly two Kubernetes nodes "
    "(one control-plane node and one worker), Kubernetes v1.36.1, and pinned "
    "Cilium 1.20.5 in IPv4 native routing mode. Two case-owned BusyBox endpoints run on different nodes. "
    "The case sends only their fixed synthetic HTTP markers over IPv4 TCP/18080. "
    "Red runs with Cilium encryption disabled. Green enables Cilium WireGuard, "
    "checks Cilium status, both configured peer address sets and live interface counters, "
    "and repeats the marker request. Positive verifies the reverse marker path. "
    "This tests Cilium-managed cross-node pod-to-pod traffic only. It does not "
    "test same-node traffic, host-to-host/node-to-pod paths, other CNIs, every "
    "cluster route/interface, production coverage, performance, or packet contents. "
    "No packet capture, public destination, real credential, or external network is used."
)


def prepare_kind(_lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "networking:\n"
        "  disableDefaultCNI: true\n"
        "nodes:\n"
        "- role: control-plane\n"
        "- role: worker\n",
        encoding="utf-8",
    )
    return profile


def _kubectl(lab, *args, timeout=60, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        *args, payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def _cilium_exec(lab, node, *args, timeout=45):
    pods = json.loads(_kubectl(
        lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "-o", "json"
    ).stdout)["items"]
    matches = [p for p in pods if p.get("spec", {}).get("nodeName") == node]
    if len(matches) != 1:
        lab.block(f"Expected one Cilium agent on node {node}; found {len(matches)}")
    return _kubectl(
        lab, "-n", "kube-system", "exec", matches[0]["metadata"]["name"],
        "-c", "cilium-agent", "--", *args, timeout=timeout,
    ).stdout


def _endpoint(name, marker, node, control_plane=False):
    command = [
        "sh", "-ec",
        f"dd if=/dev/zero of=/tmp/index.html bs={BODY_BYTES} count=1 2>/dev/null; "
        f"printf %s {marker} >>/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
    ]
    spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 1,
        "nodeSelector": {"kubernetes.io/hostname": node},
        "containers": [{
            "name": name,
            "image": IMAGE,
            "command": command,
            "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                          "limits": {"cpu": "75m", "memory": "24Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
        }],
    }
    if control_plane:
        spec["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane",
                                "operator": "Exists", "effect": "NoSchedule"}]
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE}, "spec": spec}


def _install_cilium(lab, work):
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CHART_SOURCE, "--version", CILIUM_VERSION,
                "--destination", str(work), "--registry-config", str(registry), timeout=120)
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("The downloaded Cilium Helm chart differs from the reviewed digest")
    values = work / "cilium-values.json"
    values.write_text(json.dumps({
        "ipam": {"mode": "kubernetes"},
        "kubeProxyReplacement": False,
        "rollOutCiliumPods": True,
        "routingMode": "native",
        "autoDirectNodeRoutes": True,
        "ipv4NativeRoutingCIDR": "10.244.0.0/16",
        "operator": {"replicas": 1},
        "hubble": {"enabled": False},
        "bpf": {"monitorAggregation": "none"},
        "envoy": {"enabled": False},
        "l7Proxy": False,
        "encryption": {"enabled": False, "type": "wireguard", "nodeEncryption": False},
    }))
    lab.command(
        "helm", "install", "cilium", str(chart), "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "-f", str(values), "--wait", "--timeout", "4m", timeout=260,
    )
    _kubectl(lab, "wait", "--for=condition=Ready", "node", "--all", "--timeout=120s", timeout=135)
    images = json.loads(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json").stdout)
    actual = {c.get("image") for c in images["spec"]["template"]["spec"]["containers"]
              if c.get("name") == "cilium-agent"}
    if actual != {CILIUM_IMAGE}:
        lab.block(f"Unexpected Cilium agent image: {sorted(actual)}")


def _wireguard_transfers(lab, node):
    links = json.loads(_cilium_exec(lab, node, "ip", "-j", "-s", "link", "show", "dev",
                                    WIREGUARD_INTERFACE))
    stats = links[0].get("stats64") or links[0]["stats"]
    return stats["rx"]["bytes"], stats["tx"]["bytes"]


def _status(lab, node):
    return _cilium_exec(lab, node, "sh", "-ec",
                        "cilium-dbg status | awk '/^Encryption:/ { print }'")


def _wireguard_interfaces(lab, node):
    return {link["ifname"] for link in json.loads(_cilium_exec(lab, node, "ip", "-j", "link", "show"))}


def _peer_routes(lab, node):
    items = json.loads(_kubectl(
        lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium",
        "--field-selector", f"spec.nodeName={node},status.phase=Running", "-o", "json"
    ).stdout)["items"]
    if len(items) != 1:
        lab.block("Expected one ready Cilium agent on the measured node")
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", "kube-system", "exec", items[0]["metadata"]["name"], "-c", "cilium-agent",
            "--", "cilium-dbg", "debuginfo", "--output", "json"]
    proc = subprocess.run(args, env=lab.env, capture_output=True, timeout=40)
    if proc.returncode:
        lab.block("Could not obtain Cilium's WireGuard peer state")
    interfaces = json.loads(proc.stdout)["encryption"]["wireguard"]["interfaces"]
    for interface in interfaces:
        if interface["name"] == WIREGUARD_INTERFACE and interface["peer-count"] == 1:
            peer, = interface["peers"]
            return peer["allowed-ips"]
    return []


def _marker_rounds(lab, source, destination_ip, marker, count):
    script = (
        f"for n in $(seq 1 {count}); do "
        f"wget -q -T 3 -O /tmp/saf-probe http://{destination_ip}:{PORT}/; "
        f"test $(wc -c </tmp/saf-probe) -eq {BODY_BYTES + len(marker)}; "
        f'test "$(tail -c {len(marker)} /tmp/saf-probe)" = "{marker}"; '
        'done; rm -f /tmp/saf-probe; printf verified'
    )
    result = _kubectl(lab, "-n", NAMESPACE, "exec", f"pod/{source}", "--", "sh", "-ec", script,
                      timeout=30, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == "verified"


def _create(lab, resource):
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def _wait_endpoint(lab, name):
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
             "--timeout=120s", timeout=130)
    pod = json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)
    return pod["status"]["podIP"], pod["spec"]["nodeName"]


def _enable_wireguard(lab, chart):
    values = chart.parent / "cilium-wireguard-values.json"
    values.write_text(json.dumps({
        "ipam": {"mode": "kubernetes"},
        "kubeProxyReplacement": False,
        "rollOutCiliumPods": True,
        "routingMode": "native",
        "autoDirectNodeRoutes": True,
        "ipv4NativeRoutingCIDR": "10.244.0.0/16",
        "operator": {"replicas": 1},
        "hubble": {"enabled": False},
        "bpf": {"monitorAggregation": "none"},
        "envoy": {"enabled": False},
        "l7Proxy": False,
        "encryption": {"enabled": True, "type": "wireguard", "nodeEncryption": False},
    }))
    lab.command(
        "helm", "upgrade", "cilium", str(chart), "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "-f", str(values), "--wait", "--timeout", "4m", timeout=260,
    )
    _kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
             "--timeout=180s", timeout=195)


def run(lab):
    actual_kind = lab.command("kind", "version").stdout.strip()
    if not actual_kind.startswith(f"kind {KIND_VERSION}"):
        lab.block(f"Expected Kind {KIND_VERSION}, got {actual_kind!r}")
    version = json.loads(_kubectl(lab, "version", "-o", "json").stdout)
    if version.get("serverVersion", {}).get("gitVersion") != KUBERNETES_VERSION:
        lab.block("The Kubernetes server version does not match the reviewed pin")
    nodes = json.loads(_kubectl(lab, "get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 2:
        lab.block(f"Expected exactly two Kind nodes; found {len(nodes)}")
    control = [n for n in nodes if "node-role.kubernetes.io/control-plane" in n["metadata"].get("labels", {})]
    workers = [n for n in nodes if n not in control]
    if len(control) != 1 or len(workers) != 1:
        lab.block("Expected one control-plane node and one worker")
    control_name = control[0]["metadata"]["name"]
    worker_name = workers[0]["metadata"]["name"]

    work = lab.kubeconfig.parent
    _install_cilium(lab, work)
    _kubectl(lab, "create", "namespace", NAMESPACE)
    _create(lab, _endpoint(ENDPOINTS["source"]["name"], ENDPOINTS["source"]["marker"],
                           control_name, control_plane=True))
    _create(lab, _endpoint(ENDPOINTS["destination"]["name"], ENDPOINTS["destination"]["marker"],
                           worker_name))
    source_ip, source_node = _wait_endpoint(lab, ENDPOINTS["source"]["name"])
    destination_ip, destination_node = _wait_endpoint(lab, ENDPOINTS["destination"]["name"])
    if source_node == destination_node or source_node != control_name or destination_node != worker_name:
        lab.block("The fixed-marker endpoints were not placed on the two intended distinct nodes")

    red_status = _status(lab, source_node)
    disabled = bool(re.search(r"^Encryption:\s+Disabled\s*$", red_status, re.M))
    red_interfaces = _wireguard_interfaces(lab, source_node)
    red_request = _marker_rounds(lab, ENDPOINTS["source"]["name"], destination_ip,
                              ENDPOINTS["destination"]["marker"], 1)
    lab.check("red", "Encryption is disabled and the exact cross-node marker remains readable",
              disabled
              and WIREGUARD_INTERFACE not in red_interfaces and red_request,
              {"encryption_disabled": disabled,
               "wireguard_interface_present": WIREGUARD_INTERFACE in red_interfaces,
               "cross_node": True, "exact_marker_received": red_request,
               "request_count": 1})

    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    _enable_wireguard(lab, chart)
    for expected_ip, expected_node, endpoint in (
        (source_ip, source_node, ENDPOINTS["source"]["name"]),
        (destination_ip, destination_node, ENDPOINTS["destination"]["name"]),
    ):
        if _wait_endpoint(lab, endpoint) != (expected_ip, expected_node):
            lab.block("The encryption rollout changed a fixture endpoint")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if all(re.search(r"Encryption:\s+Wireguard\s+\[.*Peers:\s*1\)?\]", _status(lab, node), re.I)
               for node in (source_node, destination_node)):
            break
        time.sleep(2)
    else:
        lab.block("Cilium did not report active WireGuard with one peer per node")
    peer_coverage = False
    forward_routes, reverse_routes = [], []
    while time.monotonic() < deadline and not peer_coverage:
        forward_routes = _peer_routes(lab, source_node)
        reverse_routes = _peer_routes(lab, destination_node)
        peer_coverage = (any(ip_address(destination_ip) in ip_network(x) for x in forward_routes)
                         and any(ip_address(source_ip) in ip_network(x) for x in reverse_routes))
        if not peer_coverage:
            time.sleep(2)
    (lab.evidence / "wireguard-peers.json").write_text(json.dumps({
        "forward_remote_ip": destination_ip, "forward_allowed_networks": forward_routes,
        "reverse_remote_ip": source_ip, "reverse_allowed_networks": reverse_routes,
    }) + "\n")
    lab.check("green", "Cilium configures reciprocal WireGuard coverage for both fixture endpoints",
              peer_coverage, {"peers_per_node": 1, "both_endpoint_ips_in_allowed_peers": peer_coverage})

    before = _wireguard_transfers(lab, source_node)
    forward = _marker_rounds(lab, ENDPOINTS["source"]["name"], destination_ip,
                             ENDPOINTS["destination"]["marker"], 4)
    after = _wireguard_transfers(lab, source_node)
    rx_delta = after[0] - before[0]
    lab.check("green", "The WireGuard interface receives the cross-node response traffic",
              forward and rx_delta >= 4 * BODY_BYTES,
              {"cross_node": True, "marker_requests": 4, "exact_payloads_received": forward,
               "wireguard_rx_delta_covers_fixture_bytes": rx_delta >= 4 * BODY_BYTES})

    reverse = _marker_rounds(lab, ENDPOINTS["destination"]["name"], source_ip,
                             ENDPOINTS["source"]["marker"], 4)
    final = _wireguard_transfers(lab, source_node)
    tx_delta = final[1] - after[1]
    lab.check("positive", "The reverse cross-node path works through the configured WireGuard interface",
              reverse and tx_delta >= 4 * BODY_BYTES,
              {"cross_node": True, "marker_requests": 4, "exact_payloads_received": reverse,
               "wireguard_tx_delta_covers_fixture_bytes": tx_delta >= 4 * BODY_BYTES})
    (lab.evidence / "wireguard-counters.json").write_text(json.dumps({
        "baseline": {"rx": before[0], "tx": before[1]},
        "after_forward": {"rx": after[0], "tx": after[1]},
        "after_reverse": {"rx": final[0], "tx": final[1]},
        "fixture_bytes_per_direction": 4 * BODY_BYTES,
    }) + "\n")
