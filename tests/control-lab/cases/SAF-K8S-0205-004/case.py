"""Verify Cilium's observed identity, port, and HTTP enforcement on owned markers."""

from hashlib import sha256
import json
from pathlib import Path
import time

SCOPE = "A single-node Kind cluster with pinned Cilium tests owned same-node identity, L4 port, and L7 HTTP policy."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
INSTALLS_CNI = True
CILIUM = "1.20.5"
CHART_SHA = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = "fixture-cilium-server"
APPROVED = "fixture-cilium-approved"
OTHER = "fixture-cilium-other"
PORT = 18080
SECOND = 18081
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


def fixture(lab, name, role, program):
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c", program],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "150m", "memory": "64Mi"}}}
    if role == "server":
        unit["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {LABEL: role}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [unit]}})


def probe(lab, source, address):
    return json.loads(lab.kubectl("exec", f"pod/{source}", "--", "python", "-c", PROBE, address, timeout=12).stdout)


def run(lab):
    install(lab)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    fixture(lab, SERVER, "server", SERVE)
    fixture(lab, APPROVED, "allowed", "import time; time.sleep(240)")
    fixture(lab, OTHER, "other", "import time; time.sleep(240)")
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=85s", timeout=95)
    address = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)["status"]["podIP"]
    before = {name: probe(lab, name, address) for name in (APPROVED, OTHER)}
    visible = all(value == "public-marker" for results in before.values() for value in results.values())
    lab.check("red", "Both owned identity classes reach both fixture paths and the second port at baseline",
              visible, {"both_clients_reach_baseline": visible})

    lab.create({"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": "owned-cilium-ingress"},
                "spec": {"endpointSelector": {"matchLabels": {LABEL: "server"}}, "ingress": [{
                    "fromEndpoints": [{"matchLabels": {LABEL: "allowed"}}],
                    "toPorts": [{"ports": [{"port": str(PORT), "protocol": "TCP"}],
                                 "rules": {"http": [{"method": "GET", "path": "^/approved$"}]}}],
                }]}})
    target = {"approved": "public-marker", "other-path": 403, "other-port": "no-connection"}
    other = {"approved": "no-connection", "other-path": "no-connection", "other-port": "no-connection"}
    deadline = time.monotonic() + 40
    after = {}
    while time.monotonic() < deadline:
        after = {name: probe(lab, name, address) for name in (APPROVED, OTHER)}
        if after == {APPROVED: target, OTHER: other}:
            break
        time.sleep(0.5)
    observed = after == {APPROVED: target, OTHER: other}
    lab.check("green", "Cilium differentiates source identity, transport port and HTTP path on new connections",
              observed, after)
    endpoint_rows = json.loads(lab.kubectl("get", "ciliumendpoints", "-o", "json").stdout)["items"]
    identities = {row["metadata"]["name"]: row.get("status", {}).get("identity", {}).get("id", 0) for row in endpoint_rows}
    attributable = all(identities.get(name, 0) > 1 for name in (SERVER, APPROVED, OTHER)) and identities[APPROVED] != identities[OTHER]
    permitted = probe(lab, APPROVED, address)["approved"] == "public-marker"
    lab.check("positive", "Cilium assigns distinct policy identities and keeps the selected path available",
              attributable and permitted, {"attributable_cilium_endpoints": attributable, "allowed_path_remains": permitted})
    (lab.evidence / "cilium-policy-observations.json").write_text(json.dumps({
        "cilium": CILIUM, "chart_sha256": CHART_SHA, "policy_fixture": "owned-cilium-ingress",
        "baseline": before, "observed": after, "endpoint_identities": identities,
        "scope": "owned same-node Pod traffic", "production_performance_tested": False,
    }, indent=2) + "\n")
