"""Verify a scoped node firewall rule alongside actual routed Pod NetworkPolicy."""

from ipaddress import IPv4Address
import json
import time

SCOPE = "Owned cross-node IPv4 Pod and Service paths on Kind with kindnet, kube-proxy iptables and fixture nftables."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = "fixture-firewall-server"
ALLOW = "fixture-firewall-allowed"
FILTER = "fixture-firewall-filtered"
POLICY = "fixture-policy-filtered"
TABLE = "saf_fixture_007"
KEY = "fixture.example/firewall-role"
PORT = 18083
SERVICE_PORT = 18084
SERVICE = "fixture-firewall-service"
MARKER = "owned-firewall-marker"
BLOCKED = "no-marker"
SERVE = """
import socketserver
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'owned-firewall-marker')
socketserver.TCPServer(('0.0.0.0', 18083), Marker).serve_forever()
"""
PROBE = """
import errno, socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.25) as peer:
        print(peer.recv(128).decode())
except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
    print('no-marker')
except OSError as error:
    if error.errno not in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        raise
    print('no-marker')
"""


def workload(lab, name, node, role, script):
    unit = {"name": "fixture", "image": IMAGE, "command": ["python", "-c", script],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}}}
    if name == SERVER:
        unit["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {KEY: role}},
                "spec": {"nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [unit]}})


def pod_ip(lab, name, node):
    obj = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    if obj["spec"]["nodeName"] != node:
        lab.block("The fixture is not on the expected owned node")
    return str(IPv4Address(obj["status"]["podIP"]))


def probe(lab, client, address, port):
    return lab.kubectl("exec", "pod/" + client, "--", "python", "-c", PROBE,
                       address, str(port), timeout=9).stdout.strip()


def matrix(lab, endpoint, expected, timeout=20):
    end = time.monotonic() + timeout
    while True:
        observed = {client: probe(lab, client, *endpoint) for client in (ALLOW, FILTER, POLICY)}
        if observed == expected or time.monotonic() >= end:
            return observed


def control_flows(lab, api_address):
    dns = lab.kubectl("exec", "pod/" + ALLOW, "--", "python", "-c",
                      "import socket; print(socket.gethostbyname('kubernetes.default.svc.cluster.local'))",
                      timeout=15).stdout.strip()
    ready = lab.kubectl("get", "--raw", "/readyz", timeout=12).stdout.strip() == "ok"
    return {"dns_returned_kubernetes_service_ip": dns == api_address, "kubernetes_ready": ready}


def observe(lab, endpoints, expected, api_address):
    return {
        "traffic": {name: matrix(lab, endpoint, expected) for name, endpoint in endpoints.items()},
        "health": control_flows(lab, api_address),
    }


def matches(observation, expected):
    return all(values == expected for values in observation["traffic"].values()) and all(observation["health"].values())


def counter(lab, node):
    report = lab.command("docker", "exec", node, "nft", "-j", "list", "counter", "ip", TABLE, "fixture_denied")
    items = json.loads(report.stdout)["nftables"]
    denied, = (entry["counter"]["packets"] for entry in items if "counter" in entry)
    return denied


def policy(lab):
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "owned-allowlist"}, "spec": {
                    "podSelector": {"matchLabels": {KEY: "server"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {"matchExpressions": [
                        {"key": KEY, "operator": "In", "values": ["approved", "firewall-source"]}]}}],
                                 "ports": [{"protocol": "TCP", "port": PORT}]}],
                }})


def run(lab):
    sender = lab.cluster + "-control-plane"
    receiver = lab.cluster + "-worker"
    nodes = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if nodes != {sender, receiver}:
        lab.block("All rule mutations must be confined to the reviewed Kind receiver")
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "ds/kindnet", "--timeout=60s", timeout=70)
    workload(lab, SERVER, receiver, "server", SERVE)
    for name, role in ((ALLOW, "approved"), (FILTER, "firewall-source"), (POLICY, "unselected")):
        workload(lab, name, sender, role, "import time; time.sleep(245)")
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=80s", timeout=90)
    destination = pod_ip(lab, SERVER, receiver)
    filtered = pod_ip(lab, FILTER, sender)
    service = lab.create({
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
        "spec": {"selector": {KEY: "server"}, "ports": [{"port": SERVICE_PORT, "targetPort": PORT}]},
    })
    endpoints = {"pod_ip": (destination, PORT),
                 "cluster_ip": (str(IPv4Address(service["spec"]["clusterIP"])), SERVICE_PORT)}
    api_address = lab.kubectl("-n", "default", "get", "service", "kubernetes",
                              "-o", "jsonpath={.spec.clusterIP}").stdout
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    kindnet = json.loads(lab.kubectl("-n", "kube-system", "get", "ds", "kindnet", "-o", "json").stdout)
    proxy = json.loads(lab.kubectl("-n", "kube-system", "get", "configmap", "kube-proxy", "-o", "json").stdout)
    proxy_config = proxy["data"]["config.conf"]
    if "mode: iptables" not in proxy_config:
        lab.block("The test requires the reviewed kube-proxy iptables profile")

    all_allowed = {ALLOW: MARKER, FILTER: MARKER, POLICY: MARKER}
    baseline = observe(lab, endpoints, all_allowed, api_address)
    lab.check("red", "All three sources reach both cross-node paths with neither fixture control active",
              matches(baseline, all_allowed), baseline)

    rules = f"""table ip {TABLE} {{
    counter fixture_denied {{}}
    chain fixture_forward {{
        type filter hook forward priority -5; policy accept;
        ip saddr {filtered} ip daddr {destination} tcp dport {PORT} counter name fixture_denied drop
    }}
}}
"""
    only_firewall = {ALLOW: MARKER, FILTER: BLOCKED, POLICY: MARKER}
    both_expected = {ALLOW: MARKER, FILTER: BLOCKED, POLICY: BLOCKED}
    policy_expected = {ALLOW: MARKER, FILTER: MARKER, POLICY: BLOCKED}
    lab.command("docker", "exec", "-i", receiver, "nft", "-f", "-", payload=rules)
    try:
        installed_rules = lab.command("docker", "exec", receiver, "nft", "-j", "list",
                                      "table", "ip", TABLE).stdout
        packets = {"before_probes": counter(lab, receiver)}
        node_only = {"traffic": {}}
        for name, endpoint in endpoints.items():
            node_only["traffic"][name] = matrix(lab, endpoint, only_firewall)
            packets[name] = counter(lab, receiver)
        node_only["health"] = control_flows(lab, api_address)
        counted = packets["before_probes"] < packets["pod_ip"] < packets["cluster_ip"]
        lab.check("green", "The owned forward rule independently counts drops on the Pod and translated Service paths",
                  counted and matches(node_only, only_firewall), {"flows": node_only, "both_paths_counted": counted})
        policy(lab)
        effective_policy = json.loads(lab.kubectl("get", "networkpolicy", "owned-allowlist", "-o", "json").stdout)
        both = observe(lab, endpoints, both_expected, api_address)
        lab.check("green", "NetworkPolicy denies a different source when the scoped node firewall is also active",
                  matches(both, both_expected), both)
    finally:
        lab.command("docker", "exec", receiver, "nft", "delete", "table", "ip", TABLE)
    policy_only = observe(lab, endpoints, policy_expected, api_address)
    lab.check("positive", "Removing the node rule restores only its source while NetworkPolicy stays active",
              matches(policy_only, policy_expected), policy_only)
    lab.kubectl("delete", "networkpolicy", "owned-allowlist")
    restored = observe(lab, endpoints, all_allowed, api_address)
    lab.check("positive", "Removing the workload policy restores both paths for all sources with DNS and API healthy",
              matches(restored, all_allowed), restored)

    evidence = {
        "profile": {"nodes": {node["metadata"]["name"]: node["status"]["nodeInfo"] for node in nodes},
                    "kindnet_images": [c["image"] for c in kindnet["spec"]["template"]["spec"]["containers"]],
                    "kube_proxy_mode": "iptables", "ip_family": "IPv4"},
        "source_pod_ips": {client: pod_ip(lab, client, sender) for client in (ALLOW, FILTER, POLICY)},
        "destination": endpoints, "api_service_ip": api_address,
        "installed_nft_table": json.loads(installed_rules), "node_drop_packets": packets,
        "effective_network_policy": effective_policy["spec"],
        "baseline": baseline, "only_node_firewall": node_only, "combined": both,
        "only_network_policy": policy_only, "restored": restored,
    }
    (lab.evidence / "firewall-compatibility-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
