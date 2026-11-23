"""Measure exact inbound and outbound node filtering on disposable Kind nodes."""

from ipaddress import IPv4Address
import json
import time

SCOPE = "Three dynamic marker ports on an owned two-node Kind host network with exact IPv4 filtering and separate counters."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = "owned-host-marker"
CLIENT = "owned-host-probe"
TABLE = "saf_fixture_010"
MARKERS = ("permitted", "ingress-fixture", "egress-fixture")
SERVE = """
import json, socketserver, sys, threading, time
class Fixture(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.marker.encode())
addresses = {}
for marker in ('permitted', 'ingress-fixture', 'egress-fixture'):
    listener = socketserver.TCPServer((sys.argv[1], 0), Fixture)
    listener.marker = marker
    addresses[marker] = listener.server_address[1]
    threading.Thread(target=listener.serve_forever, daemon=True).start()
print(json.dumps(addresses), flush=True)
time.sleep(230)
"""
PROBE = """
import errno, socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.2) as peer:
        print(peer.recv(128).decode())
except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
    print('blocked')
except OSError as error:
    if error.errno not in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        raise
    print('blocked')
"""


def workload(lab, name, node, *argv):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"nodeName": node, "hostNetwork": True, "restartPolicy": "Never",
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "marker", "image": IMAGE, "command": ["python", *argv],
                             "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                           "limits": {"cpu": "100m", "memory": "64Mi"}}}]}})


def ipv4(node):
    address, = (IPv4Address(item["address"]) for item in node["status"]["addresses"]
                if item["type"] == "InternalIP" and ":" not in item["address"])
    return str(address)


def ports(lab):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        out = lab.kubectl("logs", "pod/" + SERVER)
        if out.stdout.strip():
            observed = json.loads(out.stdout)
            if set(observed) == set(MARKERS) and all(type(p) is int and 0 < p < 65536 for p in observed.values()):
                return observed
        time.sleep(0.3)
    lab.block("Owned listener ports could not be observed")


def probe_matrix(lab, address, listeners):
    return {name: lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", PROBE, address, str(port),
                              timeout=8).stdout.strip() for name, port in listeners.items()}


def table(lab, node, hook, source, destination, port):
    content = f"""table ip {TABLE} {{
    counter fixture_drops {{}}
    chain fixture_{hook} {{
        type filter hook {hook} priority -5; policy accept;
        ip saddr {source} ip daddr {destination} tcp dport {port} counter name fixture_drops drop
    }}
}}
"""
    lab.command("docker", "exec", "-i", node, "nft", "-f", "-", payload=content)


def packets(lab, node):
    report = lab.command("docker", "exec", node, "nft", "-j", "list", "counter", "ip", TABLE, "fixture_drops")
    value, = (row["counter"]["packets"] for row in json.loads(report.stdout)["nftables"] if "counter" in row)
    return value


def run(lab):
    sender, receiver = lab.cluster + "-control-plane", lab.cluster + "-worker"
    owned = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if owned != {sender, receiver}:
        lab.block("Firewall changes are confined to the two exact owned Kind network namespaces")
    nodes = {row["metadata"]["name"]: row for row in json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]}
    source, destination = ipv4(nodes[sender]), ipv4(nodes[receiver])
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=privileged")
    workload(lab, SERVER, receiver, "-c", SERVE, destination)
    workload(lab, CLIENT, sender, "-c", "import time; time.sleep(218)")
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=80s", timeout=90)
    listeners = ports(lab)
    expected = {name: name for name in MARKERS}
    initial = probe_matrix(lab, destination, listeners)
    lab.check("red", "All three owned node-to-node listeners answer before host filtering changes",
              initial == expected, initial)
    installed = []
    try:
        for node, hook, name in ((receiver, "input", "ingress-fixture"), (sender, "output", "egress-fixture")):
            table(lab, node, hook, source, destination, listeners[name])
            installed.append(node)
        initial_counters = {node: packets(lab, node) for node in installed}
        observed = probe_matrix(lab, destination, listeners)
        ingress = packets(lab, receiver) > initial_counters[receiver]
        egress = packets(lab, sender) > initial_counters[sender]
        denied = observed == {"permitted": "permitted", "ingress-fixture": "blocked", "egress-fixture": "blocked"}
        lab.check("green", "Independent input and output counters increase only on the intended blocked paths",
                  denied and ingress and egress, {"observed_paths": observed, "input_drop_attributed": ingress,
                                                    "output_drop_attributed": egress})
        readiness = lab.kubectl("get", "--raw=/readyz").stdout.strip() == "ok"
        health = lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all",
                             "--timeout=15s", timeout=25, allow_failure=True).returncode == 0
    finally:
        for node in reversed(installed):
            lab.command("docker", "exec", node, "nft", "delete", "table", "ip", TABLE)
    rolled_back = probe_matrix(lab, destination, listeners) == expected
    lab.check("positive", "The approved marker and control plane remain reachable and rollback restores the fixture paths",
              readiness and health and rolled_back,
              {"approved_path_during_filtering": observed["permitted"] == "permitted",
               "control_plane_ready": readiness, "nodes_ready": health, "scoped_paths_restored": rolled_back})
    (lab.evidence / "node-firewall-observations.json").write_text(json.dumps({
        "baseline": initial, "observed": observed, "input_counter_increased": ingress,
        "output_counter_increased": egress, "control_plane_ready": readiness, "nodes_ready": health,
        "restored": rolled_back, "scope": "owned IPv4 host paths only",
    }, indent=2) + "\n")
