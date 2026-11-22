"""Verify authenticated, model-version-pinned failover across two owned Kind clusters."""
import ipaddress
import json
from pathlib import Path
import runpy
import tempfile
import time

from lab import Lab, NODE_IMAGE


HERE = Path(__file__).resolve().parent
NS = "saf-test"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
PORT = 8443
PRIMARY = "model-primary"
PEER = "model-peer"
ROUTER = "inference-router"
MODEL = "saf-fixture-model"
REVISION = "synthetic-v2"
STALE = "synthetic-v1"
PRIMARY_MARKER = "SAF-LOCAL-PRIMARY-0902-005"
PEER_MARKER = "SAF-LOCAL-PEER-0902-005"
SCOPE = ("Two separately owned Kubernetes v1.36.1 Kind clusters. A local fixture router reaches an "
         "owned secondary cluster through its dynamically assigned NodePort on the Kind bridge. "
         "TLS 1.3 client identity authorizes callers and authenticates peer status and inference. "
         "The router checks the expected fixture model revision before inference. Primary endpoint "
         "loss, healthy failover, denied callers, stale-peer refusal and primary recovery are live. "
         "Real global routing, service meshes, model registries, cloud/provider network and deployment "
         "policy require separate evidence.")


def wait(lab, read, matches, reason, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = read()
        if matches(value):
            return value
        time.sleep(0.45)
    lab.block(f"Timed out waiting for {reason}")


def obj(client, *args):
    return json.loads(client.kubectl(*args, "-o", "json").stdout)


def secret(client, name, entries):
    files = [f"--from-file={key}={file}" for key, file in entries.items()]
    client.kubectl("create", "secret", "generic", name, *files, "-o", "name")


def configure(client):
    client.create({"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
                   "metadata": {"name": "route-fixture-code"},
                   "data": {"endpoint.py": (HERE / "endpoint.py").read_text()}})


def pod_template(name, mode, env, identities):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": "route-fixture-code"}}]
    for location, credential in identities.items():
        mounts.append({"name": location, "mountPath": f"/{location}", "readOnly": True})
        volumes.append({"name": location, "secret": {"secretName": credential, "defaultMode": 288}})
    container = {"name": "fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-B", "/fixture/endpoint.py", mode],
                 "env": [{"name": key, "value": value} for key, value in env.items()],
                 "volumeMounts": mounts, "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                 "resources": {"requests": {"cpu": "10m", "memory": "20Mi"},
                               "limits": {"cpu": "150m", "memory": "80Mi"}}}
    if mode == "probe":
        container["command"] = ["python", "-c", "import time; time.sleep(300)"]
    else:
        container["ports"] = [{"containerPort": PORT, "name": "tls"}]
        container["readinessProbe"] = {"tcpSocket": {"port": "tls"}, "periodSeconds": 1}
    return {"metadata": {"labels": {"app": name}},
            "spec": {"terminationGracePeriodSeconds": 1, "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container], "volumes": volumes}}


def deploy(client, name, mode, env):
    template = pod_template(name, mode, env, {"tls": name})
    client.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                   "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                            "selector": {"matchLabels": {"app": name}}, "template": template}})
    rollout(client, name)


def rollout(client, name):
    client.kubectl("rollout", "status", f"deployment/{name}", "--timeout=85s", timeout=100)


def service(client, name, service_type):
    return client.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                          "spec": {"type": service_type, "selector": {"app": name},
                                   "ports": [{"name": "tls", "port": PORT, "targetPort": "tls"}]}})


def endpoints(client, name):
    data = obj(client, "get", "endpointslices", "-l", f"kubernetes.io/service-name={name}")
    return [address for record in data["items"] for endpoint in (record.get("endpoints") or [])
            if endpoint.get("conditions", {}).get("ready") is True for address in endpoint["addresses"]]


def probe(lab, event):
    result = lab.kubectl("exec", "pod/route-client", "--", "python", "-B", "/fixture/endpoint.py",
                         "probe", event, timeout=18)
    return json.loads(result.stdout)


def events(client, workload):
    output = client.kubectl("logs", f"deployment/{workload}").stdout
    return [json.loads(line) for line in output.splitlines() if line]


def check_route(lab, scenario, destination, marker):
    result = probe(lab, scenario)
    expected = {"status": 200, "result": {"route": destination, "model": MODEL,
                                         "revision": REVISION, "marker": marker}}
    lab.check("positive", f"Authorized {scenario} request reaches its approved model and revision",
              result == expected, result)


def verify(lab, peer, directory):
    peer.kubectl("create", "namespace", NS)
    version = obj(peer, "version")["serverVersion"]["gitVersion"]
    originals = obj(lab, "get", "namespace", "kube-system")["metadata"]["uid"]
    second = obj(peer, "get", "namespace", "kube-system")["metadata"]["uid"]
    lab.check("positive", "The two Kubernetes APIs have distinct cluster identities",
              originals != second and version == "v1.36.1",
              {"distinct_cluster_namespace_uids": originals != second, "peer_version": version})

    certificates = runpy.run_path(str(HERE / "pki.py"))["generate"](lab, directory)
    for client in (lab, peer):
        configure(client)
    for client, name, role in ((lab, PRIMARY, "primary"), (peer, PEER, "peer"), (lab, ROUTER, "router"),
                               (lab, "eligible-client", "eligible-client"),
                               (lab, "unassigned-client", "unassigned-client")):
        secret(client, name, certificates[role])

    node, = obj(peer, "get", "nodes")["items"]
    node_name = node["metadata"]["name"]
    peer_ip, = [value["address"] for value in node["status"]["addresses"] if value["type"] == "InternalIP"]
    peer_ip = str(ipaddress.ip_address(peer_ip))
    container = lab.command("docker", "inspect", node_name, "--format",
                            '{{index .Config.Labels "io.x-k8s.kind.cluster"}} {{(index .NetworkSettings.Networks "kind").IPAddress}}')
    if node_name != f"{peer.cluster}-control-plane" or container.stdout.split() != [peer.cluster, peer_ip]:
        lab.block("The peer node IP was not tied to the owned Kind container")

    service(lab, PRIMARY, "ClusterIP")
    service(lab, ROUTER, "ClusterIP")
    peer_service = service(peer, PEER, "NodePort")
    peer_port = peer_service["spec"]["ports"][0]["nodePort"]
    if not 30000 <= peer_port <= 32767:
        lab.block("The secondary API did not assign a normal fixture NodePort")

    deploy(lab, PRIMARY, "backend", {"MODEL_REVISION": REVISION, "MODEL_MARKER": PRIMARY_MARKER})
    deploy(peer, PEER, "backend", {"MODEL_REVISION": REVISION, "MODEL_MARKER": PEER_MARKER})
    deploy(lab, ROUTER, "router", {"PEER_IP": peer_ip, "PEER_PORT": str(peer_port)})
    for client, name in ((lab, PRIMARY), (lab, ROUTER), (peer, PEER)):
        wait(client, lambda: endpoints(client, name), lambda found: len(found) == 1, f"{name} ready target")

    client = pod_template("route-client", "probe", {},
                          {"eligible": "eligible-client", "unassigned": "unassigned-client"})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "route-client"},
                "spec": client["spec"]})
    lab.kubectl("wait", "--for=condition=Ready", "pod/route-client", "--timeout=60s", timeout=70)
    denied = {"status": 403, "result": {"result": "model-not-authorized"}}
    check_route(lab, "initial", "primary", PRIMARY_MARKER)
    initial_denial = probe(lab, "denied-primary")
    primary_logs = events(lab, PRIMARY)
    lab.check("green", "An authenticated unassigned caller is denied on the primary route",
              initial_denial == denied and [row["event"] for row in primary_logs] == ["initial", "initial"],
              {"denial": initial_denial, "no_primary_inference_for_unassigned_principal": True})

    lab.kubectl("scale", f"deployment/{PRIMARY}", "--replicas=0")
    wait(lab, lambda: obj(lab, "get", "pods", "-l", f"app={PRIMARY}")["items"],
         lambda found: not found, "the actual primary workload to terminate")
    wait(lab, lambda: endpoints(lab, PRIMARY), lambda found: not found, "primary to lose its ready targets")
    lab.check("red", "The primary workload terminates and loses its ready endpoint in the controlled outage",
              not endpoints(lab, PRIMARY), {"primary_ready_endpoints": 0, "primary_pods_terminated": True})
    check_route(lab, "failover", "peer", PEER_MARKER)
    peer_denial = probe(lab, "denied-peer")
    peer_logs = events(peer, PEER)
    expected_peer_calls = [
        {"event": "failover", "path": path, "revision": REVISION, "router_identity_authenticated": True}
        for path in ("/status", "/infer")
    ]
    lab.check("green", "The same authorization holds after authenticated failover to the peer cluster",
              peer_denial == initial_denial == denied and peer_logs == expected_peer_calls,
              {"denial": peer_denial, "peer_authenticated_router": peer_logs == expected_peer_calls,
               "unassigned_principal_never_reached_peer": len(peer_logs) == 2})

    peer.kubectl("set", "env", f"deployment/{PEER}", f"MODEL_REVISION={STALE}")
    rollout(peer, PEER)
    wait(peer, lambda: endpoints(peer, PEER), lambda found: len(found) == 1, "stale comparator endpoint")
    stale = probe(lab, "stale")
    stale_logs = events(peer, PEER)
    expected_stale = [{"event": "stale", "path": "/status", "revision": STALE,
                       "router_identity_authenticated": True}]
    lab.check("green", "A reachable stale peer is version-checked and receives no inference request",
              stale == {"status": 503, "result": {"result": "no-eligible-model",
                         "outcomes": {"primary": "unavailable", "peer": "stale-or-unverified"}}}
              and stale_logs == expected_stale,
              {"routing_response": stale, "peer_only_received_authenticated_status_request": stale_logs == expected_stale})

    lab.kubectl("scale", f"deployment/{PRIMARY}", "--replicas=1")
    rollout(lab, PRIMARY)
    wait(lab, lambda: endpoints(lab, PRIMARY), lambda found: len(found) == 1, "recovered primary endpoint")
    check_route(lab, "recovered", "primary", PRIMARY_MARKER)
    evidence = {"primary_cluster_uid": originals, "peer_cluster_uid": second,
                "peer_node_cidr_address": peer_ip, "peer_node_port": peer_port,
                "primary_initial": primary_logs, "peer_fresh": peer_logs, "peer_stale": stale_logs,
                "primary_recovered": events(lab, PRIMARY)}
    (lab.evidence / "cluster-route.json").write_text(json.dumps(evidence, indent=2) + "\n")


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-owned-route-") as temp:
        directory = Path(temp)
        peer = Lab(lab.evidence, lab.context, directory / "kubeconfig")
        existing = set(lab.command("kind", "get", "clusters").stdout.splitlines())
        if peer.cluster in existing:
            lab.block("Refusing to reuse an existing secondary cluster")
        try:
            lab.command("kind", "create", "cluster", "--name", peer.cluster, "--image", NODE_IMAGE,
                        "--kubeconfig", str(peer.kubeconfig), "--wait", "90s", timeout=420)
            verify(lab, peer, directory)
        finally:
            lab.command("kind", "delete", "cluster", "--name", peer.cluster,
                        "--kubeconfig", str(peer.kubeconfig), timeout=100)
            remaining = lab.command("kind", "get", "clusters").stdout.splitlines()
            if peer.cluster in remaining:
                lab.block("The owned peer cluster remained after deletion")
    lab.check("positive", "The owned secondary Kind cluster was removed", True, {"peer_deleted": True})
