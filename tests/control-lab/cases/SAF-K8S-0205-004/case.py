"""Verify Cilium's observed identity, port, and HTTP enforcement on owned markers."""

from hashlib import sha256
from ipaddress import IPv4Address
import json
from pathlib import Path
import time

SCOPE = "Pinned Cilium ingress, egress, TCP and Envoy HTTP policy for owned IPv4 endpoints on separate Kind nodes."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
INSTALLS_CNI = True
CILIUM = "1.20.5"
CHART_SHA = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = "fixture-cilium-server"
APPROVED = "fixture-cilium-approved"
OTHER = "fixture-cilium-other"
PORT = 18080
LABEL = "fixture.example/role"
MARKER = "owned-cilium-marker"
HERE = Path(__file__).resolve().parent

SERVE = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'owned-cilium-marker')
    def log_message(self, *args):
        pass
with ThreadingHTTPServer(('0.0.0.0', 18080), Server) as main:
    with ThreadingHTTPServer(('0.0.0.0', 18081), Server) as other:
        Thread(target=other.serve_forever, daemon=True).start()
        main.serve_forever()
"""
PROBE = """
import errno, http.client, json, sys
results = {}
for label, port, path in [('approved', 18080, '/approved'), ('other-path', 18080, '/unapproved'),
                          ('other-port', 18081, '/approved')]:
    connection = http.client.HTTPConnection(sys.argv[1], port, timeout=1.2)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        result = response.read().decode(errors='replace')
        results[label] = 'public-marker' if response.status == 200 and result == 'owned-cilium-marker' else response.status
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError, http.client.RemoteDisconnected):
        results[label] = 'no-connection'
    except OSError as error:
        if error.errno != errno.EHOSTUNREACH:
            raise
        results[label] = 'no-connection'
    finally:
        connection.close()
print(json.dumps(results))
"""


def prepare_kind(_lab, tmp):
    config = tmp / "cilium-kind.yaml"
    config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
  - role: worker
""")
    return config


def install(lab):
    folder = lab.kubeconfig.parent
    registry = folder / "helm-registry.json"
    lab.command("helm", "pull", "oci://quay.io/cilium/charts/cilium", "--version", CILIUM,
                "--destination", str(folder), "--registry-config", str(registry), timeout=115)
    chart = folder / f"cilium-{CILIUM}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CHART_SHA:
        lab.block("The chart did not match the pinned Cilium release")
    lab.command("helm", "upgrade", "--install", "cilium", str(chart), "--namespace", "kube-system",
                "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "--registry-config", str(registry), "--values", str(HERE / "cilium-values.yaml"),
                "--wait", "--timeout", "5m", timeout=320)
    lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=90s", timeout=100)
    lab.kubectl("-n", "kube-system", "rollout", "status", "ds/cilium", "--timeout=90s", timeout=100)


def fixture(lab, name, role, program, node):
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c", program],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "150m", "memory": "64Mi"}}}
    if role == "server":
        unit["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {LABEL: role}},
                "spec": {"nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [unit]}})


def probe(lab, source, address):
    return json.loads(lab.kubectl("exec", f"pod/{source}", "--", "python", "-c", PROBE, address, timeout=12).stdout)


def matrix(lab, address, expected):
    start = time.monotonic()
    while True:
        observed = {name: probe(lab, name, address) for name in (APPROVED, OTHER)}
        elapsed = time.monotonic() - start
        if observed == expected or elapsed >= 55:
            return observed, round(elapsed, 3)
        time.sleep(0.3)


def apply_policy(lab, name, role, direction, rule):
    spec = {"endpointSelector": {"matchLabels": {LABEL: role}}, direction: [rule]}
    lab.create({"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": name}, "spec": spec})
    return spec


def endpoint_rows(lab):
    rows = json.loads(lab.kubectl("get", "ciliumendpoints", "-o", "json").stdout)["items"]
    return {row["metadata"]["name"]: row["status"] for row in rows}


def map_rows(lab, pods, node, endpoint):
    agent, = [row["metadata"]["name"] for row in pods if row["spec"]["nodeName"] == node]
    listing = lab.kubectl("-n", "kube-system", "exec", "pod/" + agent, "-c", "cilium-agent", "--",
                          "cilium-dbg", "bpf", "policy", "get", str(endpoint["id"]), "-n").stdout
    return [line.split() for line in listing.splitlines() if line.startswith(("Allow", "Deny"))]


def mapped(rows, direction, identity, *, proxy):
    return any(row[:4] == ["Allow", direction, str(identity), f"{PORT}/TCP"]
               and (row[4].isdigit() if proxy else row[4] == "NONE") for row in rows)


def run(lab):
    install(lab)
    server_node = lab.cluster + "-worker"
    client_node = lab.cluster + "-control-plane"
    owned = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if owned != {server_node, client_node}:
        lab.block("Expected the reviewed two-node Kind fixture")
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    fixture(lab, SERVER, "server", SERVE, server_node)
    fixture(lab, APPROVED, "allowed", "import time; time.sleep(620)", client_node)
    fixture(lab, OTHER, "other", "import time; time.sleep(620)", client_node)
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=85s", timeout=95)
    server = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)
    address = str(IPv4Address(server["status"]["podIP"]))
    agents = json.loads(lab.kubectl("-n", "kube-system", "get", "pods",
                                    "-l", "k8s-app=cilium", "-o", "json").stdout)["items"]
    versions = {pod["spec"]["nodeName"]: {c["name"]: c["imageID"]
                for c in pod["status"]["containerStatuses"]} for pod in agents}
    node_rows = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    kernels = {node["metadata"]["name"]: node["status"]["nodeInfo"]["kernelVersion"] for node in node_rows}

    allowed = dict.fromkeys(("approved", "other-path", "other-port"), "public-marker")
    absent = {APPROVED: allowed, OTHER: allowed}
    expected_egress = {APPROVED: {**allowed, "other-port": "no-connection"}, OTHER: allowed}
    expected_combined = {APPROVED: {"approved": "public-marker", "other-path": 403, "other-port": "no-connection"},
                         OTHER: dict.fromkeys(allowed, "no-connection")}
    baseline, baseline_seconds = matrix(lab, address, absent)
    lab.check("red", "Both owned cross-node clients reach the two routes and both ports before policy",
              baseline == absent, baseline)

    ports = [{"port": str(PORT), "protocol": "TCP"}]
    egress = apply_policy(lab, "owned-l4-egress", "allowed", "egress",
                          {"toEndpoints": [{"matchLabels": {LABEL: "server"}}], "toPorts": [{"ports": ports}]})
    l4, l4_seconds = matrix(lab, address, expected_egress)
    endpoints = endpoint_rows(lab)
    l4_rows = map_rows(lab, agents, client_node, endpoints[APPROVED])
    egress_mapped = mapped(l4_rows, "Egress", endpoints[SERVER]["identity"]["id"], proxy=False)
    lab.check("green", "The sender's kernel policy map allows the server identity on the selected TCP port",
              l4 == expected_egress and egress_mapped, {"receipts": l4, "l4_map_match": egress_mapped})

    ingress = apply_policy(lab, "owned-http-ingress", "server", "ingress",
                           {"fromEndpoints": [{"matchLabels": {LABEL: "allowed"}}],
                            "toPorts": [{"ports": ports, "rules": {"http": [
                                {"method": "GET", "path": "^/approved$"}]}}]})
    combined, combined_seconds = matrix(lab, address, expected_combined)
    endpoints = endpoint_rows(lab)
    receiver_rows = map_rows(lab, agents, server_node, endpoints[SERVER])
    redirect = mapped(receiver_rows, "Ingress", endpoints[APPROVED]["identity"]["id"], proxy=True)
    distinct = endpoints[APPROVED]["identity"]["id"] != endpoints[OTHER]["identity"]["id"]
    lab.check("green", "The receiver has an approved-identity proxy redirect and Envoy denies the extra route",
              combined == expected_combined and redirect and distinct,
              {"receipts": combined, "l7_redirect": redirect, "distinct_source_identities": distinct})

    lab.kubectl("delete", "ciliumnetworkpolicy", "owned-http-ingress")
    restored_l4, ingress_removed_seconds = matrix(lab, address, expected_egress)
    lab.check("positive", "Removing HTTP ingress restores the route and second client while egress still restricts the port",
              restored_l4 == expected_egress, restored_l4)
    lab.kubectl("delete", "ciliumnetworkpolicy", "owned-l4-egress")
    restored, egress_removed_seconds = matrix(lab, address, absent)
    lab.check("positive", "Removing egress restores the second port and both source paths", restored == absent, restored)

    evidence = {
        "cilium": CILIUM, "chart_sha256": CHART_SHA,
        "profile": {"agent_images": versions, "kernels": kernels, "sender": client_node, "receiver": server_node,
                    "server_pod_ip": address, "policy_path": "cross-node IPv4 TCP", "l7": "node-local Envoy"},
        "endpoint_identities": {name: entry["identity"]["id"] for name, entry in endpoints.items()},
        "effective_policies": {"egress": egress, "ingress": ingress},
        "attributable_policy_maps": {"sender_l4": l4_rows, "receiver_l7": receiver_rows},
        "baseline": baseline, "egress": l4, "combined": combined, "ingress_removed": restored_l4, "restored": restored,
        "seconds_to_observe": {"baseline": baseline_seconds, "l4": l4_seconds, "both": combined_seconds,
                               "remove_ingress": ingress_removed_seconds, "remove_egress": egress_removed_seconds},
    }
    (lab.evidence / "cilium-policy-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
