"""Bounded ClusterIP and NetworkPolicy witness for the pinned native server Pod."""
import json
import time


NAMESPACE = "saf-0902-001"
CONTROL = "SAF-K8S-0902-001"
SERVER = "pinned-llama-readonly-model"
SERVICE = "native-serving-local"
POLICY = "native-serving-network"
ALLOWED_CLIENT = "native-serving-client-allowed"
DENIED_CLIENT = "native-serving-client-unassigned"
VERIFY = "verify"
PORT = 8080
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def _get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _peer(name, access):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": NAMESPACE,
            "labels": {"saf-lab.example/control": CONTROL,
                       "saf-lab.example/fixture": "native-serving-peer",
                       "saf-lab.example/access": access},
        },
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "runAsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "peer", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(240)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _request_script(address, path="/health", port=PORT):
    # Use urllib with proxy handling disabled; retain only the bounded status/body identity.
    code = r'''import json, sys
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
address, port, path, encoded_body = sys.argv[1:]
body = None if encoded_body == "-" else encoded_body.encode("ascii")
request = Request(f"http://{address}:{port}{path}", data=body,
                  headers={"Content-Type": "application/json"} if body is not None else {})
opener = build_opener(ProxyHandler({}))
try:
    with opener.open(request, timeout=2) as response:
        data = response.read(4096).decode("utf-8")
        if path == "/health":
            try:
                health = json.loads(data) == {"status": "ok"}
            except json.JSONDecodeError:
                health = False
            print(json.dumps({"status": response.status, "health_ok": health}, separators=(",", ":")))
        else:
            print(json.dumps({"status": response.status, "body": data}, separators=(",", ":")))
except HTTPError as error:
    print(json.dumps({"status": error.code, "body": error.read(4096).decode("utf-8")},
                     separators=(",", ":")))
except TimeoutError:
    print(json.dumps({"error": "TimeoutError"}, separators=(",", ":")))
except URLError as error:
    if isinstance(error.reason, TimeoutError):
        print(json.dumps({"error": "TimeoutError"}, separators=(",", ":")))
    else:
        raise
'''
    return code, [address, str(port), path, "-"]


def _pod_request(lab, pod, container, address, path="/health", port=PORT):
    code, args = _request_script(address, path=path, port=port)
    raw = lab.kubectl("-n", NAMESPACE, "exec", "pod/" + pod, "-c", container,
                      "--", "python", "-B", "-c", code, *args,
                      timeout=12, allow_failure=True).stdout.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Owned bounded network probe did not return JSON: {error}")


def _wait_ready(lab, name, timeout=90):
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                f"--timeout={timeout}s", timeout=timeout + 10)
    pod = _get_json(lab, "-n", NAMESPACE, "get", "pod", name)
    conditions = {row.get("type"): row.get("status") for row in
                  pod.get("status", {}).get("conditions", [])}
    labels = pod.get("metadata", {}).get("labels", {})
    expected_access = "intended" if name == ALLOWED_CLIENT else "unassigned"
    if (not pod.get("metadata", {}).get("uid") or conditions.get("Ready") != "True"
            or labels.get("saf-lab.example/control") != CONTROL
            or labels.get("saf-lab.example/fixture") != "native-serving-peer"
            or labels.get("saf-lab.example/access") != expected_access
            or pod.get("spec", {}).get("automountServiceAccountToken") is not False):
        lab.block(f"Owned network peer {name} did not become Ready")
    return pod


def _endpoint_state(lab, server_uid, server_ip):
    slices = _get_json(lab, "-n", NAMESPACE, "get", "endpointslices.discovery.k8s.io",
                       "-l", f"kubernetes.io/service-name={SERVICE}")
    endpoints = []
    for item in slices.get("items", []):
        for endpoint in item.get("endpoints", []):
            endpoints.append({
                "ready": endpoint.get("conditions", {}).get("ready"),
                "addresses": endpoint.get("addresses", []),
                "target_uid": endpoint.get("targetRef", {}).get("uid"),
                "target_name": endpoint.get("targetRef", {}).get("name"),
                "target_kind": endpoint.get("targetRef", {}).get("kind"),
                "target_namespace": endpoint.get("targetRef", {}).get("namespace"),
            })
    return len(endpoints) == 1 and endpoints[0] == {
        "ready": True, "addresses": [server_ip],
        "target_uid": server_uid, "target_name": SERVER,
        "target_kind": "Pod", "target_namespace": NAMESPACE,
    }, endpoints


def _sink_pod_ip(lab, deployment):
    pods = _get_json(lab, "-n", NAMESPACE, "get", "pods", "-l", f"app={deployment}")
    active = [pod for pod in pods.get("items", [])
              if not pod.get("metadata", {}).get("deletionTimestamp")]
    if len(active) != 1:
        lab.block(f"Expected one case-owned local sink Pod for {deployment}")
    pod = active[0]
    ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", []))
    ip = pod.get("status", {}).get("podIP")
    if not ready or not ip or not pod.get("metadata", {}).get("uid"):
        lab.block(f"Case-owned local sink {deployment} was not ready and identified")
    return pod


def run_native_serving_network(lab):
    """Test Service ingress and Pod-scoped egress against only existing owned peers."""
    server = _get_json(lab, "-n", NAMESPACE, "get", "pod", SERVER)
    server_uid = server.get("metadata", {}).get("uid")
    server_ip = server.get("status", {}).get("podIP")
    conditions = {row.get("type"): row.get("status") for row in
                  server.get("status", {}).get("conditions", [])}
    container_statuses = {row.get("name"): row for row in
                          server.get("status", {}).get("containerStatuses", [])}
    server_labels = server.get("metadata", {}).get("labels", {})
    server_container = container_statuses.get("llama-server", {})
    verifier = container_statuses.get(VERIFY, {})
    if (not server_uid or not server_ip or conditions.get("Ready") != "True"
            or server_container.get("ready") is not True or verifier.get("ready") is not True
            or not server_container.get("containerID") or not server_container.get("imageID")
            or server_labels.get("saf-lab.example/control") != CONTROL
            or server_labels.get("saf-lab.example/fixture") != "pinned-cpu-serving"):
        lab.block("The actual pinned serving Pod lacks its expected live identity/readiness")

    labels = {key: server_labels[key] for key in
              ("saf-lab.example/control", "saf-lab.example/fixture")}
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": CONTROL}},
        "spec": {"type": "ClusterIP", "selector": labels,
                 "ports": [{"name": "http", "port": PORT,
                            "targetPort": "http", "protocol": "TCP"}]},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(service))
    service_live = _get_json(lab, "-n", NAMESPACE, "get", "service", SERVICE)
    service_spec = service_live.get("spec", {})
    cluster_ip = service_spec.get("clusterIP")
    service_contract = (
        service_spec.get("type") == "ClusterIP" and bool(cluster_ip)
        and service_spec.get("selector") == labels
        and service_spec.get("ports") == [{"name": "http", "port": PORT,
                                            "protocol": "TCP", "targetPort": "http"}]
        and not service_spec.get("externalIPs") and not service_spec.get("loadBalancerIP")
    )
    if not service_contract:
        lab.block("The owned serving Service is not restricted to a ClusterIP")

    allowed_client = _peer(ALLOWED_CLIENT, "intended")
    denied_client = _peer(DENIED_CLIENT, "unassigned")
    for peer in (allowed_client, denied_client):
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(peer))
    allowed_pod = _wait_ready(lab, ALLOWED_CLIENT)
    denied_pod = _wait_ready(lab, DENIED_CLIENT)
    endpoint_deadline = time.monotonic() + 20
    endpoint_ok = False
    endpoint_rows = []
    while time.monotonic() < endpoint_deadline:
        endpoint_ok, endpoint_rows = _endpoint_state(lab, server_uid, server_ip)
        if endpoint_ok:
            break
        time.sleep(0.25)
    lab.check("positive", "Case-owned ClusterIP Service selects the ready native server Pod UID and installed image identity",
              endpoint_ok and service_contract,
              {"cluster_ip_service_only": service_contract,
               "endpoint_ready_and_uid_bound": endpoint_ok,
               "service_selector_matches_native_fixture": service_spec.get("selector") == labels})

    baseline_intended = _pod_request(lab, ALLOWED_CLIENT, "peer", cluster_ip)
    baseline_unassigned = _pod_request(lab, DENIED_CLIENT, "peer", cluster_ip)
    expected_health = {"status": 200, "health_ok": True}
    baseline_ok = baseline_intended == expected_health and baseline_unassigned == expected_health
    if not baseline_ok:
        lab.block("Both owned peers must reach the native Service before its policy is applied")
    lab.check("red", "Before native serving policy, intended and unassigned Pods reach the same Service health route",
              baseline_ok,
              {"both_owned_peers_reached_service": True, "same_fixed_health_request": True})

    allowed_sink = _sink_pod_ip(lab, "approved-local-sink")
    denied_sink = _sink_pod_ip(lab, "unapproved-local-sink")
    egress_baseline_allowed = _pod_request(lab, SERVER, VERIFY, allowed_sink["status"]["podIP"], path="/")
    egress_baseline_denied = _pod_request(lab, SERVER, VERIFY, denied_sink["status"]["podIP"], path="/")
    expected_sink = {"status": 200, "body": "synthetic-sink-ok"}
    egress_baseline_ok = (egress_baseline_allowed == expected_sink
                          and egress_baseline_denied == expected_sink)
    if not egress_baseline_ok:
        lab.block("The native Pod verifier must reach both existing owned sink Pods before policy")
    lab.check("red", "Before native serving policy, the server Pod network namespace reaches both owned sink Pods",
              egress_baseline_ok, {"both_owned_sinks_reachable_from_server_pod": egress_baseline_ok,
                     "probe_container_shares_server_pod_network_identity": True})

    policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": POLICY, "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": CONTROL}},
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": {
                    "saf-lab.example/control": CONTROL,
                    "saf-lab.example/fixture": "native-serving-peer",
                    "saf-lab.example/access": "intended",
                }}}],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
            "egress": [{
                "to": [{"podSelector": {"matchLabels": {
                    "app": "approved-local-sink", "role": "local-sink",
                    "egress-approved": "true",
                }}}],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        },
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(policy))
    observed_policy = _get_json(lab, "-n", NAMESPACE, "get", "networkpolicy", POLICY)
    selected = _get_json(lab, "-n", NAMESPACE, "get", "pods", "-l",
                         ",".join(f"{key}={value}" for key, value in labels.items()))
    selected_rows = selected.get("items", [])
    selection_exact = (len(selected_rows) == 1
                       and selected_rows[0].get("metadata", {}).get("uid") == server_uid
                       and selected_rows[0].get("metadata", {}).get("name") == SERVER)
    policy_exact = observed_policy.get("spec") == policy["spec"]
    lab.check("positive", "Native policy selects only the exact serving Pod and limits its ingress and egress peers",
              selection_exact and policy_exact,
              {"exact_native_pod_selected": selection_exact,
               "policy_spec_matches_reviewed_allowlist": policy_exact})

    deadline = time.monotonic() + 24
    inbound = None
    egress = None
    while time.monotonic() < deadline:
        inbound = {
            "intended": _pod_request(lab, ALLOWED_CLIENT, "peer", cluster_ip),
            "unassigned": _pod_request(lab, DENIED_CLIENT, "peer", cluster_ip),
        }
        egress = {
            "approved": _pod_request(lab, SERVER, VERIFY, allowed_sink["status"]["podIP"], path="/"),
            "unapproved": _pod_request(lab, SERVER, VERIFY, denied_sink["status"]["podIP"], path="/"),
        }
        if (inbound == {"intended": expected_health, "unassigned": {"error": "TimeoutError"}}
                and egress == {"approved": expected_sink, "unapproved": {"error": "TimeoutError"}}):
            break
        time.sleep(0.5)
    if inbound is None or inbound.get("intended") != expected_health:
        lab.block("The intended case-owned peer did not reach the native Service after policy")
    lab.check("positive", "Native serving Service remains reachable from the intended case-owned Pod",
              inbound.get("intended") == expected_health,
              {"intended_peer_reaches_native_health": inbound.get("intended") == expected_health})
    lab.check("red", "The same native Service health route is denied to the unassigned case-owned Pod",
              inbound.get("unassigned") == {"error": "TimeoutError"},
              {"unassigned_peer_denied": inbound.get("unassigned") == {"error": "TimeoutError"}})
    lab.check("positive", "The native serving Pod network namespace retains only its approved local egress peer",
              egress.get("approved") == expected_sink,
              {"approved_sink_reachable_from_server_pod": egress.get("approved") == expected_sink})
    lab.check("red", "The native serving Pod network namespace cannot reach the unapproved local egress peer",
              egress.get("unapproved") == {"error": "TimeoutError"},
              {"unapproved_sink_denied_from_server_pod":
                   egress.get("unapproved") == {"error": "TimeoutError"}})

    # Confirm the fixed native server remains ready after both policy directions converge.
    final_server = _get_json(lab, "-n", NAMESPACE, "get", "pod", SERVER)
    final_statuses = {row.get("name"): row for row in
                      final_server.get("status", {}).get("containerStatuses", [])}
    final_server_status = final_statuses.get("llama-server", {})
    same_server_identity = (final_server.get("metadata", {}).get("uid") == server_uid
                           and final_server_status.get("containerID") == server_container.get("containerID")
                           and final_server_status.get("imageID") == server_container.get("imageID"))
    final_ready = (final_server.get("metadata", {}).get("uid") == server_uid
                   and same_server_identity
                   and final_server_status.get("ready") is True
                   and final_statuses.get(VERIFY, {}).get("ready") is True
                   and any(row.get("type") == "Ready" and row.get("status") == "True"
                           for row in final_server.get("status", {}).get("conditions", [])))
    final_endpoint_ok, final_endpoint_rows = _endpoint_state(lab, server_uid, server_ip)
    if not final_ready:
        lab.block("Native model server readiness or Pod identity changed during the bounded policy check")
    raw = {
        "scope": "case-owned ClusterIP, native Pod ingress and same-Pod network-namespace egress only",
        "service": {"name": SERVICE, "type": service_live.get("spec", {}).get("type"),
                    "cluster_ip": cluster_ip, "selector": service_live.get("spec", {}).get("selector")},
        "native_pod": {"name": SERVER, "uid": server_uid, "pod_ip": server_ip,
                       "labels": server_labels, "ready_before_and_after": final_ready,
                       "same_pod_container_and_image_identity": same_server_identity,
                       "container_id": server_container.get("containerID"),
                       "image_id": server_container.get("imageID"),
                       "final_container_id": final_server_status.get("containerID"),
                       "final_image_id": final_server_status.get("imageID")},
        "endpoint_slices": endpoint_rows,
        "endpoint_slices_after_policy": final_endpoint_rows,
        "owned_peers": {"intended": {"name": ALLOWED_CLIENT,
                                       "uid": allowed_pod["metadata"]["uid"]},
                        "unassigned": {"name": DENIED_CLIENT,
                                       "uid": denied_pod["metadata"]["uid"]}},
        "policy_spec": observed_policy.get("spec"),
        "policy_selected_pod_uids": [row.get("metadata", {}).get("uid")
                                      for row in selected_rows],
        "before_policy": {"inbound": {"intended": baseline_intended,
                                        "unassigned": baseline_unassigned},
                          "server_pod_egress": {"approved": egress_baseline_allowed,
                                                "unapproved": egress_baseline_denied}},
        "after_policy": {"inbound": inbound, "server_pod_egress": egress},
        "egress_probe_identity": "verify container in the same Pod/network namespace; not a llama process-originated connection",
    }
    (lab.evidence / "native-serving-network.raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("positive", "Native Pod UID, container image identity, readiness, and Service endpoint remain stable through policy enforcement",
              final_ready and same_server_identity and final_endpoint_ok,
              {"same_server_pod_container_and_image": same_server_identity,
               "server_and_verifier_ready": final_ready,
               "service_endpoint_still_targets_same_ready_pod_uid": final_endpoint_ok})
