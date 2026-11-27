"""Verify mTLS peer identity and current per-request authorization in Istio."""
from hashlib import sha256
import json
from pathlib import Path
import platform
import tarfile
import time

from fixtures import container, pod, ready

SCOPE = (
    "A fresh local Kind Kubernetes v1.36.1 cluster with Istio 1.32.0 sidecars and namespace-owned "
    "ServiceAccounts. Two workload identities reach the same two owned HTTP routes before "
    "workload policy activation. The destination proxy authenticates exact SPIFFE URI SANs. "
    "Requests from fresh client proxies after a scoped authorization change distinguish the approved identity "
    "and path from independent denied controls. A separate approved identity reuses one owned "
    "HTTP/1.1 client socket for an allowed request across policy activation, then the owner gracefully replaces "
    "that exact fixture Pod and reconnects with the same identity. Application-socket reuse, "
    "destination-proxy connection IDs, injected drain hook, and version-pinned xDS acknowledgement "
    "are captured separately. Existing in-flight streams and production mesh policy coverage need "
    "further evidence."
)
ROOT = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
BACKEND = "saf-identity-target"
ALLOWED_PATH = "/allow"
OTHER_PATH = "/other"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
PILOT_IMAGE = (
    "docker.io/istio/pilot:1.32.0@sha256:"
    "5383df363d976589a51ab438831f82e9b5303dfc42128f2fb1f493b3f6acca78"
)
PROXY_IMAGE = (
    "docker.io/istio/proxyv2:1.32.0@sha256:"
    "b8d47c6d8d6e4b3fee7ae1e6f44339ec13091c24dc07f113a35efb0141a688d0"
)

ISTIO_VERSION = "1.32.0"
ISTIO_RELEASE_SHA256 = {
    "Linux-x86_64": "b9cc0d427e2742b63ade28e15332a4b5da37ebf2d777a25ba22cc91bbfd51fbf",
    "Linux-arm64": "76f220746c75b6b0098d752da941ed91afc4e0cfd6722b853172d764fb6c2173",
    "Darwin-arm64": "1d9a82445c2395f85ce3a165dc90e182ad4e52214f85c18e93db274fd6d82fbb",
    "Darwin-x86_64": "803f30507ba687f88e10ea9b6736dfb77fcc3c66c1d3ce8dc71420bfcfe27d6c",
}

def download_istio(lab, workdir):
    system = platform.system()
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    else:
        lab.block(f"Unsupported host architecture for Istio release archive: {machine}")
    key = f"{system}-{arch}"
    expected = ISTIO_RELEASE_SHA256.get(key)
    if not expected:
        lab.block(f"No verified Istio {ISTIO_VERSION} release digest for host {key}")
    release_os = "osx" if system == "Darwin" else system.lower()
    release_arch = "amd64" if arch == "x86_64" else arch
    filename = f"istio-{ISTIO_VERSION}-{release_os}-{release_arch}.tar.gz"
    archive = workdir / filename
    url = f"https://github.com/istio/istio/releases/download/{ISTIO_VERSION}/{filename}"
    lab.command("curl", "--fail", "--location", "--retry", "3", "--output", str(archive),
                url, timeout=240)
    if sha256(archive.read_bytes()).hexdigest() != expected:
        lab.block("Istio release archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        root = f"istio-{ISTIO_VERSION}/"
        wanted = (root + "bin/istioctl",)
        for member_name in wanted:
            member = bundle.getmember(member_name)
            if not member.isfile():
                lab.block(f"Istio release archive has no regular file at {member_name}")
            source = bundle.extractfile(member)
            if source is None:
                lab.block(f"Cannot read Istio release member {member_name}")
            destination = workdir / member_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
        istioctl_path = workdir / root / "bin/istioctl"
        istioctl_path.chmod(0o755)
    return istioctl_path


def install(lab):
    work = lab.kubeconfig.parent
    installer = download_istio(lab, work)
    settings = work / "istio-settings.json"
    settings.write_text(json.dumps({
        "apiVersion": "install.istio.io/v1alpha1", "kind": "IstioOperator",
        "spec": {
            "profile": "minimal",
            "values": {"pilot": {"image": PILOT_IMAGE}},
            "meshConfig": {
                "accessLogFile": "/dev/stdout",
                "accessLogFormat": "SAF-PEER|%DOWNSTREAM_PEER_URI_SAN%|%REQ(X-SAF-CASE)%|%REQ(:PATH)%|%RESPONSE_CODE%|%CONNECTION_ID%",
            },
        },
    }))
    lab.command(str(installer), "install", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "-f", str(settings), "-y", timeout=280)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", "istio-system"]
    lab.command(*args, "rollout", "status", "deployment/istiod", "--timeout=90s", timeout=100)
    response = lab.command(*args, "get", "deployment/istiod", "-o", "json").stdout
    images = [row["image"] for row in json.loads(response)["spec"]["template"]["spec"]["containers"]]
    pinned = PILOT_IMAGE in images
    lab.check("positive", "Istio control plane is ready from the pinned release",
              pinned, {"istio_version": ISTIO_VERSION, "pilot_image_pinned": pinned})
    lab.kubectl("label", "namespace", NAMESPACE, "istio-injection=enabled")


def apply_config(lab, kind, name, spec):
    lab.create({"apiVersion": "security.istio.io/v1", "kind": kind,
                "metadata": {"name": name}, "spec": spec})


def mesh_pod(lab, name, container_config, service_account):
    workload = pod(name, [container_config], serviceAccountName=service_account)
    workload["metadata"]["labels"] = {"app": name}
    workload["metadata"]["annotations"] = {"sidecar.istio.io/proxyImage": PROXY_IMAGE}
    lab.create(workload)
    ready(lab, name)
    state = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    spec = state["spec"]
    sidecars = [*spec["containers"], *(entry for entry in spec.get("initContainers", [])
                                         if entry.get("restartPolicy") == "Always")]
    proxies = [item["image"] for item in sidecars if item["name"] == "istio-proxy"]
    effective = state["spec"]["serviceAccountName"] == service_account and proxies == [PROXY_IMAGE]
    lab.check("positive", f"{name} has the reviewed sidecar and service account",
              effective, {"service_account": service_account, "proxy_pinned": proxies == [PROXY_IMAGE]})


def unasserted_mesh_pod(lab, name, container_config, service_account,
                        termination_grace_period=20):
    """Create a test-only Pod; identity and proxy are included in the grouped assertion."""
    workload = pod(name, [container_config], serviceAccountName=service_account)
    workload["spec"]["terminationGracePeriodSeconds"] = termination_grace_period
    workload["metadata"]["labels"] = {"app": name}
    workload["metadata"]["annotations"] = {
        "sidecar.istio.io/proxyImage": PROXY_IMAGE,
        "sidecar.istio.io/nativeSidecar": "true",
    }
    lab.create(workload)
    ready(lab, name)
    state = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    spec = state["spec"]
    sidecars = [*spec["containers"], *(entry for entry in spec.get("initContainers", [])
                                         if entry.get("restartPolicy") == "Always")]
    return (state["spec"].get("serviceAccountName") == service_account
            and [item["image"] for item in sidecars if item["name"] == "istio-proxy"] == [PROXY_IMAGE])


def client(lab, name, service_account):
    mesh_pod(lab, name, container("workload", image=PYTHON_IMAGE,
                                  command=["python", "-c", "import time; time.sleep(600)"]),
             service_account)


def http(lab, name, path, marker):
    code = (ROOT / "request.py").read_text()
    result = lab.kubectl("exec", name, "-c", "workload", "--", "python", "-c", code, path, marker,
                         allow_failure=True, timeout=14)
    return json.loads(result.stdout) if result.returncode == 0 else {"status": 0, "body": ""}


def logged_peer(lab, name, path, marker, status):
    peer = f"spiffe://cluster.local/ns/{NAMESPACE}/sa/{name}"
    expected = f"SAF-PEER|{peer}|{marker}|{path}|{status}|"
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        rows = lab.kubectl("logs", BACKEND, "-c", "istio-proxy").stdout.splitlines()
        for row in rows:
            if row.startswith(expected):
                connection_id = row[len(expected):].strip()
                if connection_id.isdigit():
                    return connection_id
        time.sleep(0.5)
    return None


def check_request(lab, phase, identity, path, status, marker, client_name):
    result = http(lab, client_name, path, marker)
    expected_body = "saf-identity-marker" if status == 200 else "RBAC: access denied"
    peer = logged_peer(lab, identity, path, marker, status)
    evidence = {"identity": identity, "path": path, "http_status": result["status"],
                "exact_body_matched": result["body"] == expected_body,
                "destination_proxy_confirmed_mtls_peer": peer is not None}
    lab.check(phase, f"{identity} receives HTTP {status} on {path} with the measured mTLS identity",
              result == {"status": status, "body": expected_body} and peer, evidence)
    return evidence


def persistent_client(lab, name):
    script = (ROOT / "session_client.py").read_text()
    container_config = container("workload", image=PYTHON_IMAGE, command=["python", "-c", script])
    pod_valid = unasserted_mesh_pod(lab, name, container_config, "approved", 20)
    health = "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:19091/healthz',timeout=2).read().decode().strip())"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = lab.kubectl("exec", name, "-c", "workload", "--", "python", "-c", health,
                               allow_failure=True, timeout=7)
        if response.returncode == 0 and response.stdout.strip() == "ready":
            return pod_valid
        time.sleep(0.5)
    return False


def session_identity_and_drain(lab, name):
    state = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    spec = state.get("spec", {})
    proxies = [row for row in [*spec.get("containers", []), *spec.get("initContainers", [])]
               if row.get("name") == "istio-proxy"]
    native_proxy = [row for row in spec.get("initContainers", [])
                    if row.get("name") == "istio-proxy" and row.get("restartPolicy") == "Always"]
    command = (proxies[0].get("lifecycle", {}).get("preStop", {})
               .get("exec", {}).get("command", [])) if len(proxies) == 1 else []
    drain_hook = (len(proxies) == 1 and len(native_proxy) == 1
                  and state.get("metadata", {}).get("annotations", {}).get(
                      "sidecar.istio.io/nativeSidecar") == "true"
                  and proxies[0].get("image") == PROXY_IMAGE
                  and "pilot-agent" in command and "request" in command
                  and "POST" in command and "drain" in command)
    return {
        "pod_uid": state.get("metadata", {}).get("uid", ""),
        "approved_service_account": spec.get("serviceAccountName") == "approved",
        "pinned_proxy_and_prestop_drain": bool(drain_hook),
        "grace_period_seconds": spec.get("terminationGracePeriodSeconds"),
    }


def delete_owned_session(lab, name):
    result = lab.kubectl("delete", "pod", name, "--grace-period=20", "--wait=true",
                         "--timeout=30s", allow_failure=True, timeout=40)
    absent = lab.kubectl("get", "pod", name, "-o", "name", allow_failure=True)
    deleted = (result.returncode == 0 and absent.returncode != 0
               and "notfound" in absent.stderr.lower() and name in absent.stderr)
    return deleted


def session_request(lab, client_name, path, marker):
    trigger = (
        "import sys,urllib.parse,urllib.request;"
        "query=urllib.parse.urlencode({'path':sys.argv[1],'marker':sys.argv[2]});"
        "print(urllib.request.urlopen('http://127.0.0.1:19091/request?'+query,timeout=8).read().decode())"
    )
    result = lab.kubectl("exec", client_name, "-c", "workload", "--", "python", "-c", trigger,
                         path, marker, allow_failure=True, timeout=12)
    try:
        return json.loads(result.stdout) if result.returncode == 0 else {"status": 0, "body": ""}
    except json.JSONDecodeError:
        return {"status": 0, "body": ""}


def parse_proxy_status_json(raw, target):
    required = {"CDS", "LDS", "EDS", "RDS"}
    statuses = {}
    position = 0
    decoder = json.JSONDecoder()
    try:
        while position < len(raw):
            while position < len(raw) and raw[position].isspace():
                position += 1
            if position >= len(raw):
                break
            document, position = decoder.raw_decode(raw, position)
            for resource in document.get("resources", []):
                if resource.get("node", {}).get("id") != target:
                    continue
                for config in resource.get("genericXdsConfigs", []):
                    type_url = config.get("typeUrl", "")
                    short = {
                        "envoy.config.cluster.v3.Cluster": "CDS",
                        "envoy.config.listener.v3.Listener": "LDS",
                        "envoy.config.endpoint.v3.ClusterLoadAssignment": "EDS",
                        "envoy.config.route.v3.RouteConfiguration": "RDS",
                    }.get(type_url.removeprefix("type.googleapis.com/"))
                    if short is not None:
                        statuses[short] = config.get("configStatus", "")
                # Support the legacy xdsConfig encoding used by older proxies;
                # still accept only the four exact core types and enum states.
                for config in resource.get("xdsConfig", []):
                    legacy = {
                        "clusterConfig": "CDS", "listenerConfig": "LDS",
                        "endpointConfig": "EDS", "routeConfig": "RDS",
                    }
                    for field, short in legacy.items():
                        value = config.get(field)
                        if isinstance(value, dict) and short not in statuses:
                            statuses[short] = value.get("status", "")
    except (json.JSONDecodeError, TypeError, AttributeError):
        statuses = {}
    exact = len(statuses) == len(required) and set(statuses) == required
    return {"target_proxy_id": target, "target_row_seen": exact,
            "statuses": dict(sorted(statuses.items())),
            "all_xds_types_synced": exact and all(value == "SYNCED" for value in statuses.values())}


def wait_for_proxy_ack(lab, proxy_name):
    istioctl = lab.kubeconfig.parent / f"istio-{ISTIO_VERSION}" / "bin" / "istioctl"
    deadline = time.monotonic() + 35
    target = f"{proxy_name}.{NAMESPACE}"
    last = parse_proxy_status_json("", target)
    while time.monotonic() < deadline:
        result = lab.command(str(istioctl), "proxy-status",
                             "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                             "--output", "json",
                             timeout=15, allow_failure=True)
        last = parse_proxy_status_json(result.stdout, target)
        if result.returncode == 0 and last["all_xds_types_synced"]:
            return last
        time.sleep(1)
    return last


def run(lab):
    install(lab)
    selector = {"matchLabels": {"app": BACKEND}}
    apply_config(lab, "PeerAuthentication", "owned-strict", {"selector": selector, "mtls": {"mode": "STRICT"}})
    backend_script = (ROOT / "backend_server.py").read_text()
    lab.kubectl("create", "serviceaccount", BACKEND)
    mesh_pod(lab, BACKEND, container("workload", image=PYTHON_IMAGE,
                                     command=["python", "-c", backend_script]), BACKEND)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": BACKEND},
                "spec": {"selector": {"app": BACKEND}, "ports": [{"name": "http", "port": 8080}]}})
    for name in ("approved", "other"):
        lab.kubectl("create", "serviceaccount", name)
        client(lab, name, name)

    requests = [(name, path) for name in ("approved", "other") for path in (ALLOWED_PATH, OTHER_PATH)]
    baseline = [
        check_request(lab, "red", name, path, 200, f"before-{index}", name)
        for index, (name, path) in enumerate(requests)
    ]
    # Open one fixed keep-alive HTTP/1.1 connection before policy activation.
    session_name = "approved-session"
    session_pod_valid = persistent_client(lab, session_name)
    session_before = session_request(lab, session_name, ALLOWED_PATH, "session-before-policy")
    session_before_connection = logged_peer(
        lab, "approved", ALLOWED_PATH, "session-before-policy", 200)
    session_owner_state = session_identity_and_drain(lab, session_name)
    apply_config(lab, "AuthorizationPolicy", "owned-identity-policy", {
        "selector": selector, "action": "ALLOW",
        "rules": [{"from": [{"source": {"principals": [f"cluster.local/ns/{NAMESPACE}/sa/approved"]}}],
                   "to": [{"operation": {"methods": ["GET"], "paths": [ALLOWED_PATH]}}]}],
    })
    deadline = time.monotonic() + 40
    other_identity_denial = {"status": 0, "body": ""}
    while time.monotonic() < deadline:
        other_identity_denial = http(lab, "other", ALLOWED_PATH, "propagation")
        if other_identity_denial["status"] == 403:
            break
        time.sleep(0.5)
    else:
        lab.block("The owned target proxy did not observe the authorization policy")
    other_denial_connection = logged_peer(lab, "other", ALLOWED_PATH, "propagation", 403)
    # Keep connection reuse and control-plane acknowledgement as separate outputs.
    proxy_ack = wait_for_proxy_ack(lab, BACKEND)
    session_source_ack = wait_for_proxy_ack(lab, session_name)
    # Observe the approved path after activation before checking the second route.
    session_after_policy = session_request(lab, session_name, ALLOWED_PATH, "session-after-policy")
    session_after_connection = logged_peer(
        lab, "approved", ALLOWED_PATH, "session-after-policy", 200)
    # Exercise the newly acknowledged route restriction on the same already-open
    # application connection, then observe the allowed route after its 403.
    session_denied = session_request(
        lab, session_name, OTHER_PATH, "session-denied-after-policy")
    session_denied_connection = logged_peer(
        lab, "approved", OTHER_PATH, "session-denied-after-policy", 403)
    session_allowed_after_denial = session_request(
        lab, session_name, ALLOWED_PATH, "session-allowed-after-denial")
    session_allowed_after_denial_connection = logged_peer(
        lab, "approved", ALLOWED_PATH, "session-allowed-after-denial", 200)
    existing_path_enforcement = {
        "denied_path_gets_exact_403_after_policy_ack": (
            session_denied.get("status") == 403
            and session_denied.get("body") == "RBAC: access denied"
            and session_denied_connection is not None),
        "denied_request_uses_existing_application_socket": (
            session_denied.get("request_used_prior_app_socket") is True
            and session_denied.get("request_local_port") == session_after_policy.get("local_port")),
        "destination_proxy_confirms_peer_and_denied_request": session_denied_connection is not None,
        "approved_followup_uses_same_application_socket": (
            session_allowed_after_denial.get("request_used_prior_app_socket") is True
            and session_allowed_after_denial.get("request_local_port") == session_denied.get("local_port")),
        "approved_route_after_denial_remains_200": (
            session_allowed_after_denial.get("status") == 200
            and session_allowed_after_denial.get("body") == "saf-identity-marker"
            and session_allowed_after_denial_connection is not None),
    }
    path_lifecycle = {
        "application_socket_open_after_denied_response": session_denied.get("socket_open_after_response"),
        "allowed_followup_used_prior_application_socket":
            session_allowed_after_denial.get("request_used_prior_app_socket"),
        "denied_request_socket_local_port": session_denied.get("request_local_port"),
        "socket_state_before_allowed_followup": session_denied.get("local_port"),
        "allowed_followup_request_local_port": session_allowed_after_denial.get("request_local_port"),
        "allowed_followup_response_local_port": session_allowed_after_denial.get("local_port"),
        "destination_connection_id_before_denial": session_after_connection,
        "destination_connection_id_for_denial": session_denied_connection,
        "destination_connection_changed_before_denial": (
            session_after_connection != session_denied_connection),
        "destination_connection_id_for_allowed_followup": session_allowed_after_denial_connection,
        "destination_connection_changed_after_denial": (
            session_denied_connection != session_allowed_after_denial_connection),
    }
    (lab.evidence / "established-path-enforcement-observations.json").write_text(
        json.dumps({"policy_acknowledged_before_probe": True,
                    "denied_path": session_denied,
                    "allowed_followup": session_allowed_after_denial,
                    "checks": existing_path_enforcement,
                    "observed_lifecycle": path_lifecycle}, indent=2, sort_keys=True) + "\n")
    lab.check("green", "The established application connection enforces the updated request path policy",
              all(existing_path_enforcement.values()),
              existing_path_enforcement)
    # Earlier clients can retain their mesh upstream connections across an xDS update.
    # Use new outbound proxies with the same identities for the after-policy matrix.
    for name in ("approved", "other"):
        client(lab, f"{name}-fresh", name)
    enforced = [
        check_request(lab, "green", name, path, 403, f"after-{index}", f"{name}-fresh")
        for index, (name, path) in enumerate(requests[1:])
    ]
    allowed = check_request(lab, "positive", "approved", ALLOWED_PATH, 200, "after-permitted", "approved-fresh")
    (lab.evidence / "identity-observations.json").write_text(
        json.dumps({"baseline": baseline, "denials": enforced, "permitted": allowed},
                   indent=2, sort_keys=True) + "\n"
    )
    session_app_ports = [session_before.get("local_port"), session_after_policy.get("local_port")]
    session_connection_ids = [session_before_connection, session_after_connection]
    session_connections_observed = (all(isinstance(value, str) and value.isdigit()
                                        for value in session_connection_ids))
    destination_connection_changed_after_policy = (
        session_connections_observed and session_connection_ids[0] != session_connection_ids[1])
    drain_completed = delete_owned_session(lab, session_name)
    reconnect_name = "approved-reconnected"
    reconnect_pod_valid = persistent_client(lab, reconnect_name)
    reconnect_identity = session_identity_and_drain(lab, reconnect_name)
    reconnected = session_request(lab, reconnect_name, ALLOWED_PATH, "session-reconnected")
    reconnect_connection = logged_peer(
        lab, "approved", ALLOWED_PATH, "session-reconnected", 200)
    reconnect_source_ack = wait_for_proxy_ack(lab, reconnect_name)
    reconnect_target_ack = wait_for_proxy_ack(lab, BACKEND)
    session_observations = {
        "session_pod_uses_approved_service_account_and_pinned_proxy": session_pod_valid,
        "old_session_owner_state": {
            "pod_uid_observed": bool(session_owner_state["pod_uid"]),
            "approved_service_account": session_owner_state["approved_service_account"],
            "pinned_proxy_and_prestop_drain": session_owner_state["pinned_proxy_and_prestop_drain"],
            "bounded_grace_period": session_owner_state["grace_period_seconds"] == 20,
        },
        "before_policy": session_before,
        "after_policy_approved_route": session_after_policy,
        "application_socket_local_ports": session_app_ports,
        "same_application_socket_reused": (
            all(isinstance(port, int) and port > 0 for port in session_app_ports)
            and len(set(session_app_ports)) == 1
            and session_after_policy.get("same_socket_as_prior_request") is True),
        "destination_proxy_connection_ids": session_connection_ids,
        "destination_connection_changed_after_policy": destination_connection_changed_after_policy,
        "destination_connection_change_is_observation_only": True,
        "owner_initiated_graceful_pod_replacement_completed": drain_completed,
        "reconnected_pod_identity_and_proxy": {
            "new_pod_uid": bool(reconnect_identity["pod_uid"]),
            "new_pod_uid_differs_from_drained_pod": (
                bool(reconnect_identity["pod_uid"])
                and reconnect_identity["pod_uid"] != session_owner_state["pod_uid"]),
            "approved_service_account": reconnect_identity["approved_service_account"],
            "pinned_proxy": reconnect_pod_valid,
            "pinned_proxy_prestop_drain": reconnect_identity["pinned_proxy_and_prestop_drain"],
        },
        "after_drain_approved_response": {
            "status_200_and_marker": (reconnected.get("status"), reconnected.get("body"))
                                     == (200, "saf-identity-marker"),
            "destination_proxy_connection_id": reconnect_connection,
            "new_destination_connection": (isinstance(reconnect_connection, str)
                                           and reconnect_connection.isdigit()
                                           and session_before_connection is not None
                                           and reconnect_connection != session_before_connection),
            "source_proxy_xds_ack": reconnect_source_ack,
            "destination_proxy_xds_ack": reconnect_target_ack,
        },
        "destination_proxy_connection_ids_observed": session_connections_observed,
        "other_identity_denied_before_approved_session_reuse": (
            other_identity_denial == {"status": 403, "body": "RBAC: access denied"}
            and other_denial_connection is not None),
        "other_identity_denial_connection_id": other_denial_connection,
        "proxy_xds_ack": proxy_ack,
        "established_source_proxy_xds_ack": session_source_ack,
        "expected_http_outcomes": (
            (session_before.get("status"), session_before.get("body")) == (200, "saf-identity-marker")
            and (session_after_policy.get("status"), session_after_policy.get("body")) == (200, "saf-identity-marker")
            and (reconnected.get("status"), reconnected.get("body")) == (200, "saf-identity-marker")),
    }
    (lab.evidence / "established-session-observations.json").write_text(
        json.dumps(session_observations, indent=2, sort_keys=True) + "\n"
    )
    lab.check("green", "An approved request continues over its authenticated session, then reconnects after the owner replaces the exact Pod",
              session_observations["session_pod_uses_approved_service_account_and_pinned_proxy"]
              and session_observations["old_session_owner_state"]["pinned_proxy_and_prestop_drain"]
              and session_observations["old_session_owner_state"]["bounded_grace_period"]
              and session_observations["same_application_socket_reused"]
              and session_observations["destination_proxy_connection_ids_observed"]
              and session_observations["other_identity_denied_before_approved_session_reuse"]
              and session_observations["owner_initiated_graceful_pod_replacement_completed"]
              and session_observations["reconnected_pod_identity_and_proxy"]["new_pod_uid_differs_from_drained_pod"]
              and session_observations["reconnected_pod_identity_and_proxy"]["approved_service_account"]
              and session_observations["reconnected_pod_identity_and_proxy"]["pinned_proxy"]
              and session_observations["reconnected_pod_identity_and_proxy"]["pinned_proxy_prestop_drain"]
              and session_observations["after_drain_approved_response"]["status_200_and_marker"]
              and session_observations["after_drain_approved_response"]["new_destination_connection"]
              and session_observations["expected_http_outcomes"],
              {**{name: session_observations[name] for name in (
                  "session_pod_uses_approved_service_account_and_pinned_proxy",
                  "old_session_owner_state", "same_application_socket_reused",
                  "destination_proxy_connection_ids_observed",
                  "owner_initiated_graceful_pod_replacement_completed",
                  "reconnected_pod_identity_and_proxy",
                  "other_identity_denied_before_approved_session_reuse",
                  "expected_http_outcomes",
              )}, "replacement_has_new_destination_connection":
                  session_observations["after_drain_approved_response"]["new_destination_connection"]})
    ack_results = {
        "destination_after_policy": session_observations["proxy_xds_ack"],
        "established_source_after_policy": session_observations["established_source_proxy_xds_ack"],
        "replacement_source_after_reconnect": session_observations["after_drain_approved_response"]["source_proxy_xds_ack"],
        "destination_after_reconnect": session_observations["after_drain_approved_response"]["destination_proxy_xds_ack"],
    }
    ack_ok = all(value.get("target_row_seen")
                 and set(value.get("statuses", {})) == {"CDS", "LDS", "EDS", "RDS"}
                 and all(value["statuses"].get(kind) == "SYNCED" for kind in ("CDS", "LDS", "EDS", "RDS"))
                 and value.get("all_xds_types_synced") for value in ack_results.values())
    lab.check("positive", "Istio 1.32.0 structured proxy-status independently confirms exact core xDS ACKs for the named source and destination proxies",
              ack_ok, {"observations": ack_results, "required_types": ["CDS", "LDS", "EDS", "RDS"],
                       "parsed_from": "istioctl proxy-status --output json", "all_exact_acknowledgements": ack_ok})
