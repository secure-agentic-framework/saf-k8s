"""Measure exact inbound and outbound node filtering on disposable Kind nodes."""

from ipaddress import IPv4Address
import json
import time

SCOPE = "Owned dynamic host TCP paths and the authenticated API TLS endpoint, with confined node ingress and egress filtering."
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
time.sleep(360)
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


API_PROBE = """
import socket, ssl, sys
context = ssl.create_default_context(cafile='/trust/ca.crt')
with socket.create_connection((sys.argv[1], 6443), timeout=3) as peer:
    with context.wrap_socket(peer, server_hostname=sys.argv[1]) as secured:
        print(bool(secured.version()))
"""


def workload(lab, name, node, *argv):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"nodeName": node, "hostNetwork": True, "restartPolicy": "Never",
                         "automountServiceAccountToken": False,
                         "volumes": [{"name": "trust", "configMap": {"name": "kube-root-ca.crt"}}],
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "marker", "image": IMAGE, "command": ["python", *argv],
                             "volumeMounts": [{"name": "trust", "mountPath": "/trust", "readOnly": True}],
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


def table(lab, node, hook, interface, source, destination, port):
    direction = "iifname" if hook == "input" else "oifname"
    device = json.dumps(interface)
    content = f"""table ip {TABLE} {{
    counter fixture_drops {{}}
    chain fixture_{hook} {{
        type filter hook {hook} priority -5; policy accept;
        {direction} {device} ip saddr {source} ip daddr {destination} tcp dport {port} counter name fixture_drops drop
    }}
}}
"""
    lab.command("docker", "exec", "-i", node, "nft", "-f", "-", payload=content)
    return json.loads(lab.command("docker", "exec", node, "nft", "-j", "list", "table", "ip", TABLE).stdout)


def packets(lab, node):
    report = lab.command("docker", "exec", node, "nft", "-j", "list", "counter", "ip", TABLE, "fixture_drops")
    value, = (row["counter"]["packets"] for row in json.loads(report.stdout)["nftables"] if "counter" in row)
    return value


def required_health(lab, address):
    peer = lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", API_PROBE, address,
                       timeout=11, allow_failure=True)
    ready = lab.kubectl("get", "--raw=/readyz", timeout=12).stdout.strip() == "ok"
    nodes = lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all",
                        "--timeout=12s", timeout=22, allow_failure=True)
    return {"worker_to_control_plane_authenticated_tls": peer.returncode == 0 and peer.stdout.strip() == "True",
            "apiserver_ready": ready, "both_nodes_ready": nodes.returncode == 0}


def route(lab, node, address):
    item, = json.loads(lab.command("docker", "exec", node, "ip", "-j", "route", "get", address).stdout)
    return item


def run(lab):
    sender, receiver = lab.cluster + "-worker", lab.cluster + "-control-plane"
    owned = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if owned != {sender, receiver}:
        lab.block("Firewall changes are confined to the two exact owned Kind network namespaces")
    nodes = {row["metadata"]["name"]: row for row in json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]}
    source, destination = ipv4(nodes[sender]), ipv4(nodes[receiver])
    outbound, returning = route(lab, sender, destination), route(lab, receiver, source)
    if outbound.get("prefsrc") != source or returning.get("prefsrc") != destination:
        lab.block("Expected the direct owned node IP path")
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=privileged")
    workload(lab, SERVER, receiver, "-c", SERVE, destination)
    workload(lab, CLIENT, sender, "-c", "import time; time.sleep(350)")
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=80s", timeout=90)
    listeners = ports(lab)
    expected = {name: name for name in MARKERS}
    initial = probe_matrix(lab, destination, listeners)
    health = {"baseline": required_health(lab, destination)}
    lab.check("red", "All three owned node-to-node listeners and the worker's direct API path work before filtering",
              initial == expected and all(health["baseline"].values()), {"markers": initial, **health["baseline"]})
    installed = []
    rules = {}
    counts = {}
    try:
        rules["input"] = table(lab, receiver, "input", returning["dev"], source, destination,
                               listeners["ingress-fixture"])
        installed.append(receiver)
        counts["input_before"] = packets(lab, receiver)
        only_input = probe_matrix(lab, destination, listeners)
        counts["input_after"] = packets(lab, receiver)
        valid_input = (counts["input_after"] > counts["input_before"]
                       and only_input == {**expected, "ingress-fixture": "blocked"})
        lab.check("green", "Only the selected receiver path is blocked and counted by the input rule",
                  valid_input, {"markers": only_input, "input_drop_attributed": valid_input})

        rules["output"] = table(lab, sender, "output", outbound["dev"], source, destination,
                                listeners["egress-fixture"])
        installed.append(sender)
        counts["output_before"] = packets(lab, sender)
        both = probe_matrix(lab, destination, listeners)
        counts["output_after"] = packets(lab, sender)
        health["both"] = required_health(lab, destination)
        valid_output = (counts["output_after"] > counts["output_before"] and
                        both == {"permitted": "permitted", "ingress-fixture": "blocked", "egress-fixture": "blocked"})
        lab.check("green", "The output rule blocks its own path while the direct worker-to-API TLS path stays healthy",
                  valid_output and all(health["both"].values()),
                  {"markers": both, "output_drop_attributed": valid_output, **health["both"]})
        lab.command("docker", "exec", receiver, "nft", "delete", "table", "ip", TABLE)
        installed.remove(receiver)
        only_output = probe_matrix(lab, destination, listeners)
        lab.check("positive", "Removing the input rule restores its path while the output restriction still applies",
                  only_output == {**expected, "egress-fixture": "blocked"}, only_output)
    finally:
        for node in reversed(installed):
            lab.command("docker", "exec", node, "nft", "delete", "table", "ip", TABLE)
    restored = probe_matrix(lab, destination, listeners)
    health["restored"] = required_health(lab, destination)
    lab.check("positive", "Removing both rules restores the full baseline and keeps the worker-to-API path healthy",
              restored == expected and all(health["restored"].values()), {"markers": restored, **health["restored"]})
    evidence = {
        "scope": "owned IPv4 node host TCP paths", "source": source, "destination": destination,
        "roles": {"sender": sender, "receiver": receiver}, "observed_routes": {"outbound": outbound, "return": returning},
        "listeners": listeners, "effective_rules": rules, "counter_samples": counts,
        "paths": {"baseline": initial, "only_input": only_input, "combined": both,
                  "only_output": only_output, "restored": restored}, "health": health,
    }
    (lab.evidence / "node-firewall-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
