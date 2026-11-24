"""Verify source-class egress boundaries using two owned inert services."""

import ipaddress
import json
import time

SCOPE = "Dual-stack egress source selection and policy withdrawal over two owned marker listeners, with host-network admission checked separately."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
KEY = "fixture.example/path"
CLIENT = "fixture-governed-workload"
METADATA = "fixture-node-marker"
IDENTITY = "fixture-identity-marker"
OBSERVER = "fixture-diagnostic-workload"
POLICY = "fixture-governed-paths"
FAMILIES = ("IPv4", "IPv6")
PORT = 18080
SERVER = """
import socket, socketserver, sys
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        token = self.request.recv(128).decode()
        if token:
            print(token, flush=True)
            self.request.sendall(sys.argv[1].encode())
class DualStack(socketserver.TCPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
DualStack(('::', 18080), Marker).serve_forever()
"""
PROBE = """
import socket, sys
try:
    with socket.create_connection((sys.argv[1], 18080), timeout=1.5) as peer:
        peer.sendall(sys.argv[2].encode())
        print(peer.recv(128).decode())
except TimeoutError:
    print('timeout')
"""


def pod(name, role, argv, *, host=False):
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "marker", "image": IMAGE, "command": ["python", *argv],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                          "limits": {"cpu": "100m", "memory": "48Mi"}}}]}
    if host:
        spec["hostNetwork"] = True
    if role in ("node-metadata", "approved-identity"):
        spec["containers"][0]["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {KEY: role}}, "spec": spec}


def addresses(lab, name):
    fields = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]["podIPs"]
    ips = {f"IPv{ipaddress.ip_address(row['ip']).version}": row["ip"] for row in fields}
    if set(ips) != set(FAMILIES):
        lab.block(f"The dual-stack fixture Pod {name} did not have both address families")
    return ips


def received(lab, source, destination, token):
    return lab.kubectl("exec", "pod/" + source, "--", "python", "-c", PROBE, destination, token).stdout.strip()


def matrix(lab, source, phase, owned):
    return {name: {family: received(lab, source, ip, f"{phase}-{name}-{family}")
                   for family, ip in destinations.items()} for name, destinations in owned.items()}


def expected(metadata):
    return {METADATA: dict.fromkeys(FAMILIES, metadata), IDENTITY: dict.fromkeys(FAMILIES, IDENTITY)}


def wait_matrix(lab, source, phase, owned, expected_result):
    deadline = time.monotonic() + 22
    observations = {}
    while time.monotonic() < deadline:
        observations = matrix(lab, source, phase, owned)
        if observations == expected_result:
            break
        time.sleep(0.3)
    return observations


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet", "--timeout=65s", timeout=75)
    pause = ["-c", "import time; time.sleep(180)"]
    lab.create(pod(CLIENT, "client", pause))
    lab.create(pod(OBSERVER, "observer", pause))
    lab.create(pod(METADATA, "node-metadata", ["-c", SERVER, METADATA]))
    lab.create(pod(IDENTITY, "approved-identity", ["-c", SERVER, IDENTITY]))
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=70s", timeout=80)
    owned = {name: addresses(lab, name) for name in (METADATA, IDENTITY)}
    baseline = matrix(lab, CLIENT, "before", owned)
    lab.check("red", "The governed workload reaches both owned dual-stack listeners before policy",
              baseline == expected(METADATA), {"both_listeners_reachable_on_both_families": baseline == expected(METADATA)})

    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": POLICY}, "spec": {
                    "podSelector": {"matchLabels": {KEY: "client"}}, "policyTypes": ["Egress"],
                    "egress": [{"to": [{"podSelector": {"matchLabels": {KEY: "approved-identity"}}}],
                                "ports": [{"protocol": "TCP", "port": PORT}]}],
                }})
    applied = wait_matrix(lab, CLIENT, "convergence", owned, expected("timeout"))
    lab.check("green", "The applied CNI rule blocks the denied marker on IPv4 and IPv6 while keeping the approved listener",
              applied == expected("timeout"), {"denied_and_approved_by_family": applied == expected("timeout")})
    final = matrix(lab, CLIENT, "governed", owned)
    observer = matrix(lab, OBSERVER, "observer", owned)
    logs = {name: set(lab.kubectl("logs", "pod/" + name).stdout.splitlines()) for name in owned}
    denied_tokens = {f"governed-{METADATA}-{family}" for family in FAMILIES}
    permitted_tokens = {f"governed-{IDENTITY}-{family}" for family in FAMILIES}
    health_tokens = {f"observer-{METADATA}-{family}" for family in FAMILIES}
    server_observed = {"denied_tokens_logged": bool(denied_tokens & logs[METADATA]),
                       "permitted_tokens_logged": permitted_tokens <= logs[IDENTITY],
                       "health_tokens_logged": health_tokens <= logs[METADATA]}
    lab.check("positive", "Fresh client results and listener logs distinguish enforcement from endpoint failure",
              final == expected("timeout") and observer == expected(METADATA) and
              server_observed == {"denied_tokens_logged": False, "permitted_tokens_logged": True, "health_tokens_logged": True},
              server_observed)

    host_request = lab.create(pod("fixture-host-declaration", "client", ["-c", "print('public')"], host=True),
                              dry_run=True, allow_failure=True)
    host_denied = host_request.returncode != 0 and "violates PodSecurity" in host_request.stderr and "hostNetwork" in host_request.stderr
    lab.check("green", "API admission separately rejects the declared host-network workload in the governed namespace",
              host_denied, {"host_network_declaration_rejected": host_denied})
    lab.kubectl("delete", "networkpolicy", POLICY)
    restored = wait_matrix(lab, CLIENT, "restored", owned, expected(METADATA))
    lab.check("positive", "Removing the owned policy restores the same marker paths on both IP families",
              restored == expected(METADATA), {"both_original_paths_retained": restored == expected(METADATA)})
    (lab.evidence / "metadata-path-observations.json").write_text(json.dumps({
        "addresses": owned, "baseline": baseline, "governed": final, "observer": observer,
        "listener_observations": server_observed,
        "host_network_declaration_rejected": host_denied, "restored": restored,
        "provider_or_node_metadata_contacted": False,
    }, indent=2) + "\n")
