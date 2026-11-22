"""Compare Cluster and Local external traffic policy on real Kind NodePorts."""
import http.client
import json
from pathlib import Path
import time


CONTROL_ID = "SAF-K8S-0503-011"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
SERVICE = "external-policy-fixture"
POD = "external-policy-endpoint"
LABEL = "saf.example/fixture-worker"
MARKER = "SAF-K8S-0503-011 synthetic endpoint 77c2"
NODE_PORT = 30080
POLICY = "saf-0503-011-traffic-decision"
DECISION_DENIAL = "Document the chosen external traffic mode and its routing tradeoff"
SCOPE = (
    "One fresh disposable Kubernetes v1.36.1 Kind cluster with one control-plane "
    "node and two labeled workers. A single non-privileged synthetic HTTP Pod is "
    "pinned to worker-a and exposed by one NodePort Service. The same Service, "
    "endpoint, port, and localhost-to-worker mappings are probed with explicit "
    "externalTrafficPolicy Cluster and Local values. Harmless GET requests compare "
    "the endpoint-free worker with the endpoint worker. This is a kube-proxy/Kind "
    "behavior fixture, not production approval or documentation evidence. It does "
    "not establish a cloud LoadBalancer, healthCheckNodePort behavior, client source "
    "IP preservation across Docker/Kind address rewriting, provider defaults, or "
    "production endpoint topology and availability. No public destination or packet "
    "injection is used."
)


def prepare_kind(_lab, temporary):
    """Ask Kind for separate loopback bindings on the two workers."""
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "  - role: worker\n"
        "    labels:\n"
        f"      {LABEL}: worker-a\n"
        "    extraPortMappings:\n"
        "      - containerPort: 30080\n"
        "        hostPort: 0\n"
        "        listenAddress: \"127.0.0.1\"\n"
        "        protocol: TCP\n"
        "  - role: worker\n"
        "    labels:\n"
        f"      {LABEL}: worker-b\n"
        "    extraPortMappings:\n"
        "      - containerPort: 30080\n"
        "        hostPort: 0\n"
        "        listenAddress: \"127.0.0.1\"\n"
        "        protocol: TCP\n"
    )
    return config


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def app_source():
    return (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "import json, os\n"
        f"MARKER = {MARKER!r}\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  if self.path != '/probe':\n"
        "   body = b'not found'; status = 404\n"
        "  else:\n"
        "   body = json.dumps({'marker': MARKER, 'endpoint': os.environ['POD_NAME'], "
        "'endpoint_node': os.environ['NODE_NAME']}, sort_keys=True).encode(); status = 200\n"
        "  self.send_response(status)\n"
        "  self.send_header('Content-Type', 'application/json')\n"
        "  self.send_header('Content-Length', str(len(body)))\n"
        "  self.send_header('Connection', 'close')\n"
        "  self.end_headers(); self.wfile.write(body)\n"
        " def log_message(self, fmt, *args): pass\n"
        "HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n"
    )


def endpoint_pod(worker):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": POD, "namespace": NAMESPACE,
                     "labels": {"app": SERVICE}},
        "spec": {
            "nodeSelector": {LABEL: worker},
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "endpoint", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", app_source()],
                "env": [
                    {"name": "POD_NAME", "valueFrom": {"fieldRef": {
                        "fieldPath": "metadata.name"}}},
                    {"name": "NODE_NAME", "valueFrom": {"fieldRef": {
                        "fieldPath": "spec.nodeName"}}},
                ],
                "ports": [{"name": "http", "containerPort": 8080}],
                "readinessProbe": {"tcpSocket": {"port": 8080},
                                   "periodSeconds": 1, "failureThreshold": 20},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "capabilities": {"drop": ["ALL"]},
                                     "readOnlyRootFilesystem": True},
            }],
        },
    }


def service(policy):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {
            "type": "NodePort",
            "externalTrafficPolicy": policy,
            "selector": {"app": SERVICE},
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080,
                       "nodePort": NODE_PORT, "protocol": "TCP"}],
        },
    }


def wait_for(lab, resource, name, predicate, timeout=75):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = as_json(lab, "get", resource, name)
        if predicate(last):
            return last
        time.sleep(0.5)
    return last


def request(host_port):
    """Direct localhost request; expose outcome classes, not unstable error text."""
    connection = http.client.HTTPConnection("127.0.0.1", host_port, timeout=1.5)
    try:
        connection.request("GET", "/probe", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        record = {"outcome": "http_response", "http_status": response.status}
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = {}
        record.update({"marker": parsed.get("marker"),
                       "endpoint": parsed.get("endpoint"),
                       "endpoint_node": parsed.get("endpoint_node")})
        return record
    except (OSError, http.client.HTTPException):
        return {"outcome": "no_http_response"}
    finally:
        connection.close()


def sample(host_port, endpoint_node, *, expect_forwarding):
    deadline = time.monotonic() + 25
    while True:
        results = [request(host_port) for _ in range(3)]
        summary = {
            "expected_marker_responses": len(marker_successes(results, endpoint_node)),
            "no_http_responses": sum(record["outcome"] == "no_http_response"
                                     for record in results),
        }
        key = "expected_marker_responses" if expect_forwarding else "no_http_responses"
        if summary[key] == len(results) or time.monotonic() >= deadline:
            return summary
        time.sleep(0.5)


def marker_successes(results, endpoint_node):
    return [record for record in results
            if record.get("outcome") == "http_response"
            and record.get("http_status") == 200
            and record.get("marker") == MARKER
            and record.get("endpoint") == POD
            and record.get("endpoint_node") == endpoint_node]


def observe_decision_gate(lab):
    def propose(annotations=None):
        update = {"spec": {"externalTrafficPolicy": "Cluster"}}
        if annotations is not None:
            update["metadata"] = {"annotations": annotations}
        return lab.kubectl("patch", "service", SERVICE, "--type=merge",
                           "--dry-run=server", "-o", "json", "-p", json.dumps(update),
                           allow_failure=True)

    def policy_denied(result):
        return (result.returncode != 0 and "Forbidden" in result.stderr
                and POLICY in result.stderr and DECISION_DENIAL in result.stderr)

    before = propose()
    lab.check("red", "The API accepts a mode change without a decision record before enforcement",
              before.returncode == 0, {"dry_run_admitted": before.returncode == 0})
    lab.apply(Path(__file__).with_name("decision-policy.yaml"))
    deadline = time.monotonic() + 20
    missing = propose()
    while missing.returncode == 0 and time.monotonic() < deadline:
        time.sleep(1)
        missing = propose()
    lab.check("green", "Admission denies the same undocumented mode change",
              policy_denied(missing), {"matched_policy_denial": policy_denied(missing)})
    justified = {
        "saf.example/external-traffic-mode": "Local",
        "saf.example/external-traffic-rationale": "Cluster reaches worker A through both entry nodes.",
    }
    mismatched = propose(justified)
    lab.check("green", "Admission rejects a decision for the wrong mode",
              policy_denied(mismatched),
              {"matched_policy_denial": policy_denied(mismatched)})
    justified["saf.example/external-traffic-mode"] = "Cluster"
    documented = propose(justified)
    stored = as_json(lab, "get", "service", SERVICE)
    lab.check("positive", "Admission permits the matching documented change as a dry run",
              documented.returncode == 0 and stored["spec"]["externalTrafficPolicy"] == "Local",
              {"documented_change_admitted": documented.returncode == 0,
               "stored_mode": stored["spec"]["externalTrafficPolicy"]})


def run(lab):
    nodes = as_json(lab, "get", "nodes")["items"]
    worker_nodes = {}
    for node in nodes:
        labels = node.get("metadata", {}).get("labels", {})
        role = labels.get(LABEL)
        if role:
            worker_nodes[role] = node["metadata"]["name"]
    host_ports = {}
    if set(worker_nodes) != {"worker-a", "worker-b"}:
        lab.block("Expected the two labeled worker nodes")
    for role, node in worker_nodes.items():
        mapping = lab.command("docker", "port", node, f"{NODE_PORT}/tcp").stdout.strip()
        host, _, port = mapping.rpartition(":")
        if host != "127.0.0.1" or not port.isdigit():
            lab.block(f"Expected one loopback mapping for {role}")
        host_ports[role] = int(port)

    endpoint_node = worker_nodes["worker-a"]
    pod = endpoint_pod("worker-a")
    lab.kubectl("apply", "-f", "-", payload=json.dumps(pod))
    lab.kubectl("wait", "pod/" + POD, "--for=condition=Ready", "--timeout=100s",
                timeout=110)
    pod_record = as_json(lab, "get", "pod", POD)
    endpoint_on_expected_worker = (
        pod_record.get("status", {}).get("phase") == "Running"
        and pod_record.get("spec", {}).get("nodeName") == endpoint_node
    )
    lab.check("positive", "One ready synthetic endpoint is on the known worker-a node",
              endpoint_on_expected_worker,
              {"pod": POD, "pod_phase": pod_record.get("status", {}).get("phase"),
               "endpoint_on_worker_a": endpoint_on_expected_worker})

    initial_service = service("Cluster")
    lab.kubectl("apply", "-f", "-", payload=json.dumps(initial_service))
    deadline = time.monotonic() + 60
    endpoint_slice = None
    matching = []
    while time.monotonic() < deadline:
        slices = as_json(lab, "get", "endpointslices",
                         "-l", f"kubernetes.io/service-name={SERVICE}")
        matching = [endpoint for item in slices.get("items", [])
                    for endpoint in item.get("endpoints", [])]
        if (len(matching) == 1 and matching[0].get("nodeName") == endpoint_node
                and matching[0].get("conditions", {}).get("ready") is True):
            endpoint_slice = matching[0]
            break
        time.sleep(0.5)
    lab.check("positive", "Service EndpointSlice has exactly the ready worker-a endpoint",
              endpoint_slice is not None,
              {"endpoint_count": len(matching), "ready_endpoint_on_worker_a": endpoint_slice is not None})

    # This is the counterfactual red arm: with Cluster routing, both actual worker
    # NodePorts can reach the one backend, including the node with no local endpoint.
    cluster_local = sample(host_ports["worker-a"], endpoint_node, expect_forwarding=True)
    cluster_remote = sample(host_ports["worker-b"], endpoint_node, expect_forwarding=True)
    lab.check("red", "Cluster mode serves the sole endpoint from both worker NodePorts",
              cluster_local["expected_marker_responses"] == cluster_remote["expected_marker_responses"] == 3,
              {"service_policy": "Cluster", "service_type": "NodePort",
               "local_samples": cluster_local, "remote_samples": cluster_remote})

    # Change only the policy field: same Service UID, NodePort, selector and Pod.
    before = as_json(lab, "get", "service", SERVICE)
    lab.kubectl("patch", "service", SERVICE, "--type=merge", "-p",
                 '{"spec":{"externalTrafficPolicy":"Local"}}')
    after = wait_for(lab, "service", SERVICE,
                     lambda value: value.get("spec", {}).get("externalTrafficPolicy") == "Local")
    if after["spec"].get("externalTrafficPolicy") != "Local":
        lab.block("The API never reported the requested Local mode")
    endpoint_after = as_json(lab, "get", "pod", POD)
    same_service_backend = (
        before.get("metadata", {}).get("uid") == after.get("metadata", {}).get("uid")
        and before.get("spec", {}).get("clusterIP") == after.get("spec", {}).get("clusterIP")
        and before.get("spec", {}).get("ports") == after.get("spec", {}).get("ports")
        and before.get("spec", {}).get("selector") == after.get("spec", {}).get("selector")
        and pod_record.get("metadata", {}).get("uid") ==
            endpoint_after.get("metadata", {}).get("uid")
    )
    lab.check("positive", "Only externalTrafficPolicy changed on the existing Service",
              same_service_backend,
              {"same_service_uid": before.get("metadata", {}).get("uid") ==
                                   after.get("metadata", {}).get("uid"),
               "same_cluster_ip": before.get("spec", {}).get("clusterIP") ==
                                  after.get("spec", {}).get("clusterIP"),
               "same_node_port": before.get("spec", {}).get("ports") ==
                                 after.get("spec", {}).get("ports"),
               "same_selector": before.get("spec", {}).get("selector") ==
                                after.get("spec", {}).get("selector"),
               "same_endpoint_pod_uid": pod_record.get("metadata", {}).get("uid") ==
                                         endpoint_after.get("metadata", {}).get("uid")})

    remote_local = sample(host_ports["worker-b"], endpoint_node, expect_forwarding=False)
    local_local = sample(host_ports["worker-a"], endpoint_node, expect_forwarding=True)
    lab.check("green", "Local mode preserves local success and removes remote forwarding",
              local_local["expected_marker_responses"] == remote_local["no_http_responses"] == 3,
              {"service_policy": "Local", "service_type": "NodePort",
               "local_samples": local_local, "remote_samples": remote_local})
    observe_decision_gate(lab)
