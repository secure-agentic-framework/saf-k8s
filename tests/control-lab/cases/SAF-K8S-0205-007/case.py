"""Verify a scoped node firewall rule alongside actual routed Pod NetworkPolicy."""

from ipaddress import IPv4Address
import json
import time

SCOPE = "Owned cross-node Kind IPv4 Pod traffic with kindnet policy and a case-only nftables forward table."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = "fixture-firewall-server"
ALLOW = "fixture-firewall-allowed"
FILTER = "fixture-firewall-filtered"
POLICY = "fixture-policy-filtered"
TABLE = "saf_fixture_007"
KEY = "fixture.example/firewall-role"
PORT = 18083
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
    with socket.create_connection((sys.argv[1], 18083), timeout=1.25) as peer:
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


def probe(lab, client, address):
    return lab.kubectl("exec", "pod/" + client, "--", "python", "-c", PROBE, address, timeout=8).stdout.strip()


def matrix(lab, address, expected, timeout=17):
    end = time.monotonic() + timeout
    while True:
        observed = {client: probe(lab, client, address) for client in (ALLOW, FILTER, POLICY)}
        if observed == expected or time.monotonic() >= end:
            return observed


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
    all_allowed = {ALLOW: MARKER, FILTER: MARKER, POLICY: MARKER}
    baseline = matrix(lab, destination, all_allowed)
    lab.check("red", "All three cross-node fixture paths reach the marker before either control is applied",
              baseline == all_allowed, baseline)

    rules = f"""table ip {TABLE} {{
    counter fixture_denied {{}}
    chain fixture_forward {{
        type filter hook forward priority -5; policy accept;
        ip saddr {filtered} ip daddr {destination} tcp dport {PORT} counter name fixture_denied drop
    }}
}}
"""
    lab.command("docker", "exec", "-i", receiver, "nft", "-f", "-", payload=rules)
    try:
        zero = counter(lab, receiver)
        before_policy = {ALLOW: MARKER, FILTER: BLOCKED, POLICY: MARKER}
        node_only = matrix(lab, destination, before_policy)
        nft_hit = counter(lab, receiver) > zero
        policy(lab)
        both_expected = {ALLOW: MARKER, FILTER: BLOCKED, POLICY: BLOCKED}
        both = matrix(lab, destination, both_expected)
        matched = nft_hit and node_only == before_policy and both == both_expected
        lab.check("green", "The node counter attributes its selected drop and NetworkPolicy denies the additional source",
                  matched, {"node_firewall_counter_increased": nft_hit, "node_only": node_only, "combined": both})
        lab.kubectl("delete", "networkpolicy", "owned-allowlist")
        recovered = matrix(lab, destination, before_policy)
    finally:
        lab.command("docker", "exec", receiver, "nft", "delete", "table", "ip", TABLE)
    restored = matrix(lab, destination, all_allowed)
    lab.check("positive", "Removing each test control restores only its affected paths and keeps the approved path available",
              recovered == before_policy and restored == all_allowed,
              {"policy_removed": recovered, "rules_removed": restored})
    (lab.evidence / "firewall-compatibility-observations.json").write_text(json.dumps({
        "path": "cross-node IPv4 Pod ingress", "kind_cni": "kindnet", "kube_proxy_mode": "iptables",
        "node_firewall": "isolated nftables IPv4 forward table", "node_drop_counter_increased": nft_hit,
        "baseline": baseline, "node_firewall_only": node_only, "combined": both,
        "after_policy_removal": recovered, "after_fixture_cleanup": restored,
    }, indent=2) + "\n")
