"""Owned-workload Cilium peer-authentication and WireGuard configuration fixture."""
from hashlib import sha256
from ipaddress import ip_address, ip_network
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import time

CONTROL_ID = "SAF-K8S-0504-002"
CILIUM_VERSION = "1.20.5"
CILIUM_CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0504-002-cilium"
CLIENT = "owned-client"
SERVER_LOCAL = "owned-server-local"
SERVER_REMOTE = "owned-server-remote"
PORT = 8080
MARKER = "saf-0504-002-owned-inert-response-68d2"
ROLE_KEY = "saf-k8s.example/0504-002-role"

SCOPE = (
    "Fresh disposable three-node Kind cluster (one control-plane and two workers), "
    "Kubernetes v1.36.1, Cilium 1.20.5 with chart-pinned SPIRE 1.15.5. Only three "
    "case-owned Pods exchange ordinary HTTP GETs: one client and one server on the "
    "same worker, plus a server on the other worker. Baseline and authenticated "
    "requests use direct owned Pod IPs. Independent Cilium agent authentication "
    "logs and per-flow WireGuard counters on native routing are retained as signals. No packet capture, "
    "traffic interception, unrelated workload access, or production inference."
)


def prepare_kind(lab, temporary):
    config = temporary / "kind.yaml"
    config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.244.0.0/16
nodes:
  - role: control-plane
  - role: worker
  - role: worker
""")
    return config


def kubectl(lab, *args, timeout=45, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(5, timeout - 5)}s", *args, timeout=timeout, **kwargs,
    )


def get_json(lab, *args):
    return json.loads(kubectl(lab, *args, "-o", "json").stdout)


def wait_pod(lab, name):
    kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
            "--timeout=150s", timeout=160)
    pod_data = get_json(lab, "-n", NAMESPACE, "get", f"pod/{name}")
    ip = pod_data.get("status", {}).get("podIP")
    node = pod_data.get("spec", {}).get("nodeName")
    if not ip or not node:
        lab.block(f"Owned fixture {name} has no Pod IP or scheduled node")
    return {"ip": ip, "node": node}


def wait_cilium_endpoint_identities(lab, names, timeout=45):
    deadline = time.monotonic() + timeout
    found = {}
    while time.monotonic() < deadline:
        entries = get_json(lab, "-n", NAMESPACE, "get", "ciliumendpoints")["items"]
        found = {item["metadata"]["name"]: item.get("status", {}).get("identity", {}).get("id", 0)
                 for item in entries}
        if all(found.get(name, 0) > 1 for name in names):
            break
        time.sleep(0.5)
    ok = all(found.get(name, 0) > 1 for name in names) and len({found[name] for name in names}) == len(names)
    lab.check("positive", "Cilium assigned identities to each owned fixture Pod", ok,
              {"distinct_fixture_identities": ok})
    return {name: found[name] for name in names}


def fixture_pod(name, role, node, command, *, port=None):
    spec = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {ROLE_KEY: role, "saf-k8s.example/fixture": "0504-002",
                                "saf-k8s.example/owned-endpoint": name}},
        "spec": {
            "nodeName": node,
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "fixture", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", command],
                "readinessProbe": ({"httpGet": {"path": "/health", "port": PORT},
                                    "periodSeconds": 2, "failureThreshold": 20}
                                   if port else
                                   {"exec": {"command": ["python", "-c", "pass"]},
                                    "periodSeconds": 2, "failureThreshold": 20}),
                "ports": ([{"name": "http", "containerPort": PORT}] if port else []),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True},
            }],
        },
    }
    return spec


SERVER_CODE = r'''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body=("''' + MARKER + r'''|"+self.path).encode()
  self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''
CLIENT_SLEEP = "import time; time.sleep(3600)"


def policy():
    # Cilium's supported v2 policy API: require mutual authentication on the
    # selected client->server and server ingress paths, scoped to TCP/8080.
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "owned-peer-auth-required", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {"matchLabels": {ROLE_KEY: "client"}},
            "egress": [{
                "toEndpoints": [{"matchLabels": {ROLE_KEY: "server"}}],
                "authentication": {"mode": "required"},
                "toPorts": [{"ports": [{"port": str(PORT), "protocol": "TCP"}],
                             }],
            }],
        },
    }


def server_ingress_policy():
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "owned-peer-auth-required-ingress", "namespace": NAMESPACE},
        "spec": {
            "endpointSelector": {"matchLabels": {ROLE_KEY: "server"}},
            "ingress": [{
                "fromEndpoints": [{"matchLabels": {ROLE_KEY: "client"}}],
                "authentication": {"mode": "required"},
                "toPorts": [{"ports": [{"port": str(PORT), "protocol": "TCP"}],
                             }],
            }],
        },
    }


def request(lab, host, path):
    code = r'''import json,sys,urllib.error,urllib.request
try:
 with urllib.request.urlopen("http://"+sys.argv[1]+":8080"+sys.argv[2],timeout=6) as r:
  print(json.dumps({"status":r.status,"body":r.read().decode()}))
except urllib.error.HTTPError as e: print(json.dumps({"status":e.code,"body":e.read().decode(errors="replace")}))
except (OSError,TimeoutError) as e: print(json.dumps({"status":None,"error":type(e).__name__+":"+str(e)}))
'''
    result = kubectl(lab, "-n", NAMESPACE, "exec", f"pod/{CLIENT}", "-c", "fixture", "--",
                     "python", "-c", code, host, path, timeout=20)
    return json.loads(result.stdout.strip())


def cilium_pod_on_node(lab, node):
    pods = get_json(lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium")
    for pod in pods["items"]:
        if pod.get("spec", {}).get("nodeName") == node:
            return pod["metadata"]["name"]
    lab.block(f"No Cilium agent Pod found on fixture node {node}")


def auth_log_evidence(lab, client_node, server_node, client_id, server_id):
    """Return only matching Cilium auth lines from the two fixture nodes."""
    lines_by_node = {}
    needle = "Successfully authenticated"
    for node in sorted({client_node, server_node}):
        agent = cilium_pod_on_node(lab, node)
        result = kubectl(lab, "-n", "kube-system", "logs", f"pod/{agent}",
                         "-c", "cilium-agent", "--since=90s", "--timestamps=true",
                         timeout=30)
        selected = [line for line in result.stdout.splitlines()
                    if needle in line and "authType=spire" in line and "module=agent.controlplane.auth " in line
                    and set(re.findall(r"(?:localIdentity|remoteIdentity)=(\d+)", line))
                    == {str(client_id), str(server_id)}]
        lines_by_node[node] = selected[-8:]
    return lines_by_node


def wireguard_state(lab, node):
    agent = cilium_pod_on_node(lab, node)
    result = kubectl(lab, "-n", "kube-system", "exec", f"pod/{agent}", "-c",
                     "cilium-agent", "--", "cilium-dbg", "debuginfo", "--output", "json",
                     timeout=30)
    data = json.loads(result.stdout)
    return data.get("encryption", {}).get("wireguard", {})


def scoped_flow_request(lab, target, source_port):
    code = r"""import http.client,json,sys
connection = http.client.HTTPConnection(sys.argv[1], 8080, timeout=8,
                                        source_address=("0.0.0.0", int(sys.argv[2])))
connection.request("GET", "/owned/wireguard-proof")
response = connection.getresponse()
print(json.dumps({"status": response.status, "body": response.read().decode()}))
connection.close()
"""
    result = kubectl(lab, "-n", NAMESPACE, "exec", f"pod/{CLIENT}", "-c", "fixture", "--",
                     "python", "-c", code, target, str(source_port), timeout=20)
    return json.loads(result.stdout)


def wireguard_ingress_counter(lab, node, sender, receiver, source_port, target_port):
    device = "cilium_wg0"
    links = json.loads(lab.command("docker", "exec", node, "ip", "-j", "-details",
                                    "link", "show", "dev", device).stdout)
    if len(links) != 1 or links[0].get("linkinfo", {}).get("info_kind") != "wireguard":
        lab.block(f"Owned fixture node {node} did not expose a WireGuard device")
    table = f"saf_owned_{source_port}_{target_port}"
    source = ip_address(sender["ip"])
    destination = ip_address(receiver["ip"])
    rules = f"""
table netdev {table} {{
  counter matched {{}}
  chain fixture {{
    type filter hook ingress device "{device}" priority 0; policy accept;
    ip saddr {source} ip daddr {destination} tcp sport {source_port} tcp dport {target_port} counter name "matched"
  }}
}}
"""
    lab.command("docker", "exec", "-i", node, "nft", "-f", "-", payload=rules)

    def count():
        result = lab.command("docker", "exec", node, "nft", "-j", "list", "counter",
                             "netdev", table, "matched")
        entry = next((item["counter"] for item in json.loads(result.stdout)["nftables"]
                      if "counter" in item), None)
        if entry is None or not isinstance(entry.get("packets"), int):
            lab.block(f"WireGuard counter did not report integer packets on {node} ingress")
        return entry["packets"]
    return count


def compare_wireguard_flows(lab, fixture):
    observations = {}
    client = fixture[CLIENT]
    for name, source_port in ((SERVER_LOCAL, 38081), (SERVER_REMOTE, 38082)):
        target = fixture[name]
        request_ingress = wireguard_ingress_counter(lab, target["node"], client, target, source_port, PORT)
        response_ingress = wireguard_ingress_counter(lab, client["node"], target, client, PORT, source_port)
        before = [request_ingress(), response_ingress()]
        response = scoped_flow_request(lab, target["ip"], source_port)
        fulfilled = (response.get("status") == 200
                     and response.get("body") == MARKER + "|/owned/wireguard-proof")
        after = [request_ingress(), response_ingress()]
        cross_node = target["node"] != client["node"]
        seen = [count > 0 for count in after]
        observations[name] = {
            "source_ip": client["ip"], "target_ip": target["ip"],
            "source_port": source_port, "target_port": PORT,
            "request_and_response_before": before, "request_and_response_after": after,
            "cross_node": cross_node,
        }
        (lab.evidence / "fixture-wireguard-paths.json").write_text(
            json.dumps(observations, indent=2) + "\n")
        lab.check("positive", f"WireGuard interface counters show the expected owned path to {name}",
                  fulfilled and before == [0, 0] and seen == [cross_node, cross_node],
                  {"request_fulfilled": fulfilled, "initial_counters_zero": before == [0, 0],
                   "cross_node": cross_node, "request_on_server_wireguard_ingress": seen[0],
                   "response_on_client_wireguard_ingress": seen[1]})


def wg_peer_for_path(state, pod_ip, node_ip):
    matches = []
    for interface in state.get("interfaces", []):
        if interface.get("name") != "cilium_wg0":
            continue
        for peer in interface.get("peers") or []:
            addresses = {ip_address(pod_ip), ip_address(node_ip)}
            if any(address in ip_network(cidr, strict=False)
                   for address in addresses for cidr in peer.get("allowed-ips", [])):
                matches.append({"public_key": peer.get("public-key"),
                                "last_handshake_time": peer.get("last-handshake-time"),
                                "both_directions": peer.get("transfer-rx", 0) > 0 and peer.get("transfer-tx", 0) > 0,
                                "allowed_ips": peer.get("allowed-ips", [])})
    return matches


def recent_handshake(peer, max_age_seconds=300):
    value = peer.get("last_handshake_time")
    if not value:
        return False
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    age = (datetime.now(timezone.utc) - stamp.astimezone(timezone.utc)).total_seconds()
    return 0 <= age <= max_age_seconds


def run(lab):
    kind = lab.command("kind", "version").stdout.strip()
    if not kind.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, found {kind}")
    version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, found {version}")

    # The bundled server image runs as 1000:1000. Prepare only the private
    # socket directory inside the just-created Kind nodes.
    kind_nodes = lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines()
    if len(kind_nodes) != 3 or any(not node.startswith(lab.cluster + "-") for node in kind_nodes):
        lab.block("Unexpected Kind nodes for the owned SPIRE fixture")
    for node in kind_nodes:
        lab.command("docker", "exec", node, "install", "-d", "-m", "0700", "-o", "1000", "-g", "1000",
                    "/var/run/spire-server/sockets")

    cfg = lab.kubeconfig.parent
    registry = cfg / "helm-registry.json"
    lab.command("helm", "pull", "oci://quay.io/cilium/charts/cilium", "--version",
                CILIUM_VERSION, "--destination", str(cfg), "--registry-config", str(registry),
                timeout=120)
    chart = cfg / f"cilium-{CILIUM_VERSION}.tgz"
    digest = sha256(chart.read_bytes()).hexdigest()
    if digest != CILIUM_CHART_SHA256:
        lab.block(f"Cilium chart SHA-256 mismatch: {digest}")
    values = Path(__file__).with_name("cilium-values.yaml")
    lab.command("helm", "upgrade", "--install", "cilium", str(chart),
                "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "--namespace", "kube-system", "--registry-config", str(registry),
                "--values", str(values), "--wait", "--timeout", "8m", timeout=500)
    installed = json.loads(lab.command(
        "helm", "get", "values", "cilium", "--kubeconfig", str(lab.kubeconfig),
        "--kube-context", f"kind-{lab.cluster}", "--namespace", "kube-system",
        "--all", "-o", "json").stdout)
    configured = (installed.get("encryption", {}).get("enabled") is True and
                  installed.get("encryption", {}).get("type") == "wireguard" and
                  installed.get("routingMode") == "native" and installed.get("autoDirectNodeRoutes") is True and
                  installed.get("authentication", {}).get("enabled") is True and
                  installed.get("authentication", {}).get("mutual", {}).get("spire", {}).get("enabled") is True)
    if not configured:
        lab.block(f"Installed Helm values do not confirm auth and WireGuard settings: {installed}")
    kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
            "--timeout=240s", timeout=250)
    kubectl(lab, "-n", "kube-system", "rollout", "status", "deployment/cilium-operator",
            "--timeout=240s", timeout=250)
    kubectl(lab, "-n", "cilium-spire", "rollout", "status", "daemonset/spire-agent",
            "--timeout=240s", timeout=250)
    kubectl(lab, "-n", "cilium-spire", "rollout", "status", "statefulset/spire-server",
            "--timeout=240s", timeout=250)
    nodes = get_json(lab, "get", "nodes")["items"]
    node_ips = {n["metadata"]["name"]: next(row["address"] for row in n["status"]["addresses"]
                                          if row["type"] == "InternalIP" and ":" not in row["address"])
                for n in nodes}
    workers = sorted(n["metadata"]["name"] for n in nodes
                     if "node-role.kubernetes.io/control-plane" not in n["metadata"].get("labels", {}))
    if len(workers) != 2:
        lab.block(f"Expected exactly two worker nodes, found {workers}")
    lab.check("positive", f"Pinned Cilium {CILIUM_VERSION} and bundled SPIRE are ready",
              True, {"kind": kind, "kubernetes": version, "cilium_chart": CILIUM_VERSION,
                     "chart_sha256": digest, "spire_version": "1.15.5",
                     "worker_count": len(workers), "installed_values_confirmed": configured,
                     "encryption": "wireguard enabled"})

    namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}}
    kubectl(lab, "create", "-f", "-", payload=json.dumps(namespace))
    # Same-node source and target on worker 1; cross-node target on worker 2.
    for obj in (
        fixture_pod(CLIENT, "client", workers[0], CLIENT_SLEEP),
        fixture_pod(SERVER_LOCAL, "server", workers[0], SERVER_CODE, port=PORT),
        fixture_pod(SERVER_REMOTE, "server", workers[1], SERVER_CODE, port=PORT),
    ):
        kubectl(lab, "create", "-f", "-", payload=json.dumps(obj))
    fixture = {name: wait_pod(lab, name) for name in (CLIENT, SERVER_LOCAL, SERVER_REMOTE)}
    if fixture[CLIENT]["node"] != fixture[SERVER_LOCAL]["node"]:
        lab.block("Same-node source/server placement was not achieved")
    if fixture[CLIENT]["node"] == fixture[SERVER_REMOTE]["node"]:
        lab.block("Cross-node server placement was not achieved")
    identities = wait_cilium_endpoint_identities(lab, (CLIENT, SERVER_LOCAL, SERVER_REMOTE))

    baseline_auth = {}
    for name in (SERVER_LOCAL, SERVER_REMOTE):
        result = request(lab, fixture[name]["ip"], "/owned/probe")
        matched = result.get("status") == 200 and result.get("body") == MARKER + "|/owned/probe"
        lab.check("red", f"Baseline owned GET reaches {name}", matched,
                  {"target": name, "response": result})
        baseline_auth[name] = auth_log_evidence(
            lab, fixture[CLIENT]["node"], fixture[name]["node"], identities[CLIENT], identities[name])
    no_baseline_auth = not any(lines for nodes in baseline_auth.values() for lines in nodes.values())
    lab.check("red", "There is no SPIRE authentication event for either fixture pair before policy",
              no_baseline_auth, {"no_fixture_pair_authentication": no_baseline_auth})

    for obj in (policy(), server_ingress_policy()):
        kubectl(lab, "apply", "-f", "-", payload=json.dumps(obj))
    kubectl(lab, "-n", NAMESPACE, "get", "ciliumnetworkpolicies", "-o", "name")
    # Let CNP reach the three selected endpoints before issuing the green probes.
    time.sleep(3)
    auth = {}
    for name in (SERVER_LOCAL, SERVER_REMOTE):
        result = request(lab, fixture[name]["ip"], "/owned/probe")
        matched = result.get("status") == 200 and result.get("body") == MARKER + "|/owned/probe"
        lab.check("green", f"Cilium-required-auth owned GET reaches {name}", matched,
                  {"target": name, "response": result})
        # Capture the Cilium-side signal immediately after each unique fixture
        # request so the same-node claim cannot be inferred from cross-node logs.
        auth[name] = auth_log_evidence(
            lab, fixture[CLIENT]["node"], fixture[name]["node"], identities[CLIENT], identities[name])
    (lab.evidence / "fixture-authentication.json").write_text(
        json.dumps({"before_policy": baseline_auth, "after_policy": auth}, indent=2) + "\n")
    local_seen = any("remoteNodeID=0," in line for line in auth[SERVER_LOCAL][fixture[CLIENT]["node"]])
    remote_seen = all(any(re.search(r"remoteNodeID=[1-9]\d*,", line) for line in logs)
                      for logs in auth[SERVER_REMOTE].values())
    lab.check("positive", "Cilium agent logs show successful SPIRE authentication on both paths",
              local_seen and remote_seen,
              {"same_node_exact_identity_pair": local_seen,
               "cross_node_exact_identity_pair": remote_seen,
               "log_match": "Successfully authenticated; authType=spire; module=agent.controlplane.auth"})

    compare_wireguard_flows(lab, fixture)

    source_wg = wireguard_state(lab, fixture[CLIENT]["node"])
    target_wg = wireguard_state(lab, fixture[SERVER_REMOTE]["node"])
    source_peer = wg_peer_for_path(source_wg, fixture[SERVER_REMOTE]["ip"], node_ips[fixture[SERVER_REMOTE]["node"]])
    target_peer = wg_peer_for_path(target_wg, fixture[CLIENT]["ip"], node_ips[fixture[CLIENT]["node"]])
    source_key = get_json(lab, "get", "ciliumnode", fixture[CLIENT]["node"])["metadata"]["annotations"].get("network.cilium.io/wg-pub-key")
    destination_key = get_json(lab, "get", "ciliumnode", fixture[SERVER_REMOTE]["node"])["metadata"]["annotations"].get("network.cilium.io/wg-pub-key")
    peer_ok = bool(len(source_peer) == len(target_peer) == 1 and source_key != destination_key and
                   source_peer[0].get("public_key") and target_peer[0].get("public_key") and
                   source_peer[0]["public_key"] == destination_key and target_peer[0]["public_key"] == source_key and
                   source_peer[0]["both_directions"] and target_peer[0]["both_directions"] and
                   recent_handshake(source_peer[0]) and recent_handshake(target_peer[0]))
    lab.check("positive", "Reciprocal WireGuard peers for the two workload nodes have recent handshakes and traffic",
              peer_ok,
              {"reciprocal_peer_and_scope": peer_ok,
               "handshake_window_seconds": 300,
               "same_node_wireguard_coverage": "outside the documented WireGuard path"})
