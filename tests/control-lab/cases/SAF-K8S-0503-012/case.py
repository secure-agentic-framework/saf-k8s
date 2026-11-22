"""Compare NodePort peer addresses with Cluster and Local traffic policies."""
import ipaddress
import json
import time


CONTROL_ID = "SAF-K8S-0503-012"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
SERVICE = "source-ip-fixture"
POD = "source-ip-endpoint"
LABEL = "saf.example/source-ip-worker"
NODE_PORT = 30080
MARKER = "SAF-K8S-0503-012 harmless source-ip marker 91b4"
SCOPE = (
    "One fresh disposable Kubernetes v1.36.1 Kind cluster with one control-plane "
    "node and one worker, both owned by the by-ID runner and pinned to the same "
    "kindest/node digest. A single ready, non-privileged synthetic HTTP Pod runs "
    "on that worker behind one NodePort Service. A runner-owned Python client "
    "container attaches to the local Docker bridge shared by the Kind nodes. Its "
    "actual bridge IPv4 is read from scoped Docker inspection, then ordinary HTTP "
    "requests from that container reach the worker's bridge IPv4 and NodePort. "
    "The same NodePort, node, Service, and endpoint serve a live marker in explicit "
    "Cluster and Local arms. The endpoint reports the TCP peer address from the "
    "accepted socket; no HTTP forwarding header is used. This measures Kind, its "
    "Docker bridge, and kube-proxy only. It does not verify cloud load balancers, "
    "proxy-protocol or forwarded-header configuration, production policy rollout, "
    "or the per-Service governance obligation. No public endpoint, spoofing, data "
    "capture, or packet method is used."
)


def prepare_kind(_lab, temporary):
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "  - role: worker\n"
        "    labels:\n"
        f"      {LABEL}: worker-a\n"
    )
    return config


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def app_source():
    return (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "import json\n"
        f"MARKER = {MARKER!r}\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  if self.path != '/probe':\n"
        "   body = b'not found'; status = 404\n"
        "  else:\n"
        "   body = json.dumps({'marker': MARKER, 'peer_ip': self.client_address[0]}, "
        "sort_keys=True).encode(); status = 200\n"
        "  self.send_response(status)\n"
        "  self.send_header('Content-Type', 'application/json')\n"
        "  self.send_header('Content-Length', str(len(body)))\n"
        "  self.send_header('Connection', 'close')\n"
        "  self.end_headers(); self.wfile.write(body)\n"
        " def log_message(self, fmt, *args): pass\n"
        "HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n"
    )


def endpoint_pod():
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": POD, "namespace": NAMESPACE,
                     "labels": {"app": SERVICE}},
        "spec": {
            "nodeSelector": {LABEL: "worker-a"},
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "endpoint", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", app_source()],
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


def peer_is_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except (ValueError, TypeError):
        return False


CLIENT_REQUEST = r'''
import http.client, json, sys
connection = http.client.HTTPConnection(sys.argv[1], int(sys.argv[2]), timeout=3)
try:
    connection.request("GET", "/probe", headers={"Connection": "close"})
    response = connection.getresponse()
    body = response.read()
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    print(json.dumps({"http_response": True, "http_status_200": response.status == 200,
        "marker_matches": payload.get("marker") == sys.argv[3],
        "peer_ipv4": payload.get("peer_ip") if isinstance(payload.get("peer_ip"), str) else "",
        "response_received": True}, sort_keys=True))
except (OSError, http.client.HTTPException):
    print(json.dumps({"http_response": False, "http_status_200": False,
        "marker_matches": False, "peer_ipv4": "", "response_received": False},
        sort_keys=True))
finally:
    connection.close()
'''


def get_client_ip(lab, bridge, node_ip, client_name):
    result = lab.command(
        "docker", "inspect", "--format",
        '{{.Name}} {{.State.Running}} {{.Config.Image}} {{index .Config.Labels "saf.example/owner"}}',
        client_name)
    fields = result.stdout.split()
    exact_name = len(fields) == 4 and fields[0] == f"/{client_name}" and fields[3] == lab.cluster
    networks = json.loads(lab.command("docker", "inspect", "--format",
                                      "{{json .NetworkSettings.Networks}}", client_name).stdout)
    attached = networks.get(bridge)
    address = attached.get("IPAddress", "") if attached else ""
    actual = peer_is_ipv4(address)
    pinned_image = exact_name and fields[2] == PYTHON_IMAGE
    running = exact_name and fields[1] == "true"
    lab.check("positive", "The exact owned client container is running on the selected Kind bridge",
              exact_name and running and pinned_image and attached is not None and actual
              and address != node_ip,
              {"exact_container_name": exact_name,
               "container_running": running,
               "digest_pinned_image_matches": pinned_image,
               "attached_to_selected_bridge": attached is not None,
               "client_bridge_ipv4_valid": actual,
               "client_ip_differs_from_node_ip": actual and address != node_ip})
    return address


def request(lab, client_name, node_ip):
    result = lab.command("docker", "exec", client_name, "python", "-c", CLIENT_REQUEST,
                         node_ip, str(NODE_PORT), MARKER)
    receipt = json.loads(result.stdout)
    peer = receipt.get("peer_ipv4", "")
    receipt["peer_ipv4_valid"] = peer_is_ipv4(peer)
    return receipt


def sample(lab, client_name, node_ip, client_ip, count=3):
    receipts = []
    for _ in range(count):
        receipt = request(lab, client_name, node_ip)
        peer = receipt["peer_ipv4"]
        receipt.update({"peer_is_client_ipv4": peer == client_ip,
                        "peer_is_entry_node_ipv4": peer == node_ip})
        receipts.append(receipt)
    return {
        "request_count": count,
        "responses_received": sum(row["response_received"] for row in receipts),
        "all_http_responses": all(row["http_response"] for row in receipts),
        "all_status_200": all(row["http_status_200"] for row in receipts),
        "all_markers_match": all(row["marker_matches"] for row in receipts),
        "all_peer_addresses_are_ipv4": all(row["peer_ipv4_valid"] for row in receipts),
        "all_peers_match_client": all(row["peer_is_client_ipv4"] for row in receipts),
        "peer_is_entry_node_for_all": all(row["peer_is_entry_node_ipv4"] for row in receipts),
        "receipts": receipts,
    }


def await_samples(lab, client_name, node_ip, client_ip, *, preserved):
    deadline = time.monotonic() + 25
    while True:
        result = sample(lab, client_name, node_ip, client_ip)
        expected_peer = all(row["peer_is_client_ipv4"] == preserved
                            for row in result["receipts"])
        if ((result["all_status_200"] and result["all_markers_match"]
             and result["all_peer_addresses_are_ipv4"] and expected_peer)
                or time.monotonic() >= deadline):
            return result
        time.sleep(0.5)


def selected_bridge(lab, cluster, node_names):
    node_records = {}
    for node_name in node_names:
        fields = lab.command(
            "docker", "inspect", "--format",
            '{{.Name}} {{index .Config.Labels "io.x-k8s.kind.cluster"}} '
            '{{index .Config.Labels "io.x-k8s.kind.role"}}', node_name).stdout.split()
        exact_name = len(fields) == 3 and fields[0] == f"/{node_name}"
        expected_role = "control-plane" if node_name.endswith("-control-plane") else "worker"
        exact_owner = exact_name and fields[1:] == [cluster, expected_role]
        lab.check("positive", "Each inspected node is an exact node owned by this Kind cluster",
                  exact_owner, {"exact_container_name": exact_name,
                                "kind_cluster_label_matches": exact_owner,
                                "expected_kind_role_matches": exact_owner})
        node_records[node_name] = json.loads(lab.command(
            "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}",
            node_name).stdout)

    common = set.intersection(*(set(networks) for networks in node_records.values()))
    candidates = []
    for network_name in sorted(common):
        options = lab.command("docker", "network", "inspect", "--format", "{{.Driver}} {{.Scope}}",
                              network_name).stdout.split()
        if options == ["bridge", "local"]:
            candidates.append(network_name)
    lab.check("positive", "Kind nodes share exactly one local Docker bridge",
              len(candidates) == 1,
              {"shared_local_bridge_found": len(candidates) == 1,
               "shared_local_bridge_count": len(candidates)})
    network_name = candidates[0]
    ips = {}
    for node_name, record in node_records.items():
        address = record.get(network_name, {}).get("IPAddress", "")
        ips[node_name] = address
    endpoint_node = f"{cluster}-worker"
    lab.check("positive", "The worker has a usable IPv4 on the selected Kind bridge",
              endpoint_node in ips and peer_is_ipv4(ips.get(endpoint_node)),
              {"selected_worker_found": endpoint_node in ips,
               "worker_bridge_ipv4_valid": peer_is_ipv4(ips.get(endpoint_node, "")),
               "selected_network_is_local_bridge": True})
    return network_name, ips[endpoint_node]


def run(lab):
    expected_nodes = {f"{lab.cluster}-control-plane", f"{lab.cluster}-worker"}
    actual_nodes = set(lab.command("kind", "get", "nodes", "--name", lab.cluster)
                       .stdout.split())
    lab.check("positive", "Kind reports exactly the two expected owned nodes",
              actual_nodes == expected_nodes,
              {"exact_node_set": actual_nodes == expected_nodes,
               "node_count": len(actual_nodes)})

    client_name = f"{lab.cluster}-client"
    client_created = False
    try:
        network_name, node_ip = selected_bridge(lab, lab.cluster, sorted(expected_nodes))
        endpoint_pod_record = endpoint_pod()
        lab.kubectl("apply", "-f", "-", payload=json.dumps(endpoint_pod_record))
        lab.kubectl("wait", f"pod/{POD}", "--for=condition=Ready", "--timeout=100s",
                    timeout=110)
        pod = as_json(lab, "get", "pod", POD)
        endpoint_ip = pod.get("status", {}).get("podIP", "")
        endpoint_ready = (
            pod.get("status", {}).get("phase") == "Running"
            and pod.get("status", {}).get("containerStatuses", [{}])[0].get("ready") is True
            and pod.get("spec", {}).get("nodeName") == f"{lab.cluster}-worker"
            and peer_is_ipv4(endpoint_ip)
        )
        lab.check("positive", "One ready harmless endpoint is on the selected worker",
                  endpoint_ready,
                  {"pod_ready": endpoint_ready,
                   "endpoint_on_selected_worker": pod.get("spec", {}).get("nodeName")
                   == f"{lab.cluster}-worker",
                   "endpoint_pod_ipv4_valid": peer_is_ipv4(endpoint_ip)})

        service_record = service("Cluster")
        lab.kubectl("apply", "-f", "-", payload=json.dumps(service_record))
        slice_ready = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            slices = as_json(lab, "get", "endpointslices",
                             "-l", f"kubernetes.io/service-name={SERVICE}")
            endpoints = [item for part in slices.get("items", [])
                         for item in part.get("endpoints", [])]
            slice_ready = (len(endpoints) == 1
                           and endpoints[0].get("conditions", {}).get("ready") is True
                           and endpoints[0].get("nodeName") == f"{lab.cluster}-worker"
                           and endpoints[0].get("addresses") == [endpoint_ip])
            if slice_ready:
                break
            time.sleep(0.5)
        lab.check("positive", "The Service has exactly the same ready worker endpoint",
                  slice_ready,
                  {"single_ready_endpoint_on_selected_worker": slice_ready})

        lab.command("docker", "run", "--detach", "--name", client_name,
                    "--label", f"saf.example/owner={lab.cluster}", "--network", network_name,
                    "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", PYTHON_IMAGE,
                    "python", "-c", "import time; time.sleep(600)")
        client_created = True
        client_ip = get_client_ip(lab, network_name, node_ip, client_name)

        baseline = await_samples(lab, client_name, node_ip, client_ip, preserved=False)
        lab.check("red", "Cluster baseline serves the live marker but rewrites the client peer",
                  baseline["all_http_responses"] and baseline["all_status_200"]
                  and baseline["all_markers_match"] and baseline["all_peer_addresses_are_ipv4"]
                  and all(not row["peer_is_client_ipv4"] for row in baseline["receipts"])
                  and baseline["responses_received"] == baseline["request_count"],
                  {"service_policy": "Cluster", "node_port": NODE_PORT,
                   "receipt_summary": {key: baseline[key] for key in (
                       "request_count", "responses_received", "all_http_responses",
                       "all_status_200", "all_markers_match", "all_peer_addresses_are_ipv4",
                       "all_peers_match_client", "peer_is_entry_node_for_all")},
                   "all_connections_rewritten": all(not row["peer_is_client_ipv4"]
                                                    for row in baseline["receipts"])})

        before = as_json(lab, "get", "service", SERVICE)
        lab.kubectl("patch", "service", SERVICE, "--type=merge", "-p",
                     '{"spec":{"externalTrafficPolicy":"Local"}}')
        after = wait_for(lab, "service", SERVICE,
                         lambda value: value.get("spec", {}).get("externalTrafficPolicy") == "Local")
        pod_after = as_json(lab, "get", "pod", POD)
        slices_after = as_json(lab, "get", "endpointslices",
                               "-l", f"kubernetes.io/service-name={SERVICE}")
        endpoints_after = [item for part in slices_after.get("items", [])
                           for item in part.get("endpoints", [])]
        same_ready_endpoint = (
            pod_after.get("status", {}).get("phase") == "Running"
            and pod_after.get("status", {}).get("containerStatuses", [{}])[0].get("ready") is True
            and pod_after.get("status", {}).get("podIP") == endpoint_ip
            and pod_after.get("spec", {}).get("nodeName") == f"{lab.cluster}-worker"
            and len(endpoints_after) == 1
            and endpoints_after[0].get("conditions", {}).get("ready") is True
            and endpoints_after[0].get("nodeName") == f"{lab.cluster}-worker"
            and endpoints_after[0].get("addresses") == [endpoint_ip]
        )
        same_route = (
            before.get("metadata", {}).get("uid") == after.get("metadata", {}).get("uid")
            and before.get("spec", {}).get("clusterIP") == after.get("spec", {}).get("clusterIP")
            and before.get("spec", {}).get("ports") == after.get("spec", {}).get("ports")
            and before.get("spec", {}).get("selector") == after.get("spec", {}).get("selector")
            and pod.get("metadata", {}).get("uid") ==
                pod_after.get("metadata", {}).get("uid")
            and same_ready_endpoint
        )
        lab.check("positive", "Only policy changed; the same NodePort and endpoint remain",
                  same_route and after.get("spec", {}).get("externalTrafficPolicy") == "Local",
                  {"same_service_uid": before.get("metadata", {}).get("uid") ==
                                       after.get("metadata", {}).get("uid"),
                   "same_node_port": before.get("spec", {}).get("ports") ==
                                     after.get("spec", {}).get("ports"),
                   "same_selector": before.get("spec", {}).get("selector") ==
                                    after.get("spec", {}).get("selector"),
                   "same_endpoint_pod_uid": same_route,
                   "same_ready_endpoint_after_patch": same_ready_endpoint,
                   "policy_is_local": after.get("spec", {}).get("externalTrafficPolicy") == "Local"})

        preserved = await_samples(lab, client_name, node_ip, client_ip, preserved=True)
        lab.check("green", "Local serves the same live marker with the actual client peer IPv4",
                  preserved["all_http_responses"] and preserved["all_status_200"]
                  and preserved["all_markers_match"] and preserved["all_peer_addresses_are_ipv4"]
                  and preserved["all_peers_match_client"]
                  and preserved["responses_received"] == preserved["request_count"],
                  {"service_policy": "Local", "node_port": NODE_PORT,
                   "receipt_summary": {key: preserved[key] for key in (
                       "request_count", "responses_received", "all_http_responses",
                       "all_status_200", "all_markers_match", "all_peer_addresses_are_ipv4",
                       "all_peers_match_client", "peer_is_entry_node_for_all")},
                   "rewritten_connection_count": sum(not row["peer_is_client_ipv4"]
                                                    for row in preserved["receipts"])})
        (lab.evidence / "observed-ip-tuples.json").write_text(json.dumps({
            "client_bridge_ipv4": client_ip, "entry_node_bridge_ipv4": node_ip,
            "cluster_mode": [row["peer_ipv4"] for row in baseline["receipts"]],
            "local_mode": [row["peer_ipv4"] for row in preserved["receipts"]],
        }, indent=2) + "\n")
    finally:
        if client_created:
            lab.command("docker", "rm", "--force", client_name, allow_failure=True)
            remaining = lab.command("docker", "ps", "-aq", "--filter", f"name=^/{client_name}$")
            exact_container_absent = not remaining.stdout.strip()
            lab.check("positive", "The exact owned client container is absent after cleanup",
                      exact_container_absent,
                      {"exact_client_container_absent": exact_container_absent})
