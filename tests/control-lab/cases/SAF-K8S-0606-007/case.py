"""Observe the owned runner's harmless command and public marker access."""
from hashlib import sha256
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
CHART = "https://helm.cilium.io/tetragon-1.8.0.tgz"
CHART_HASH = "38a10bca4bffd3efac7cbcc7f99b24dbcd3ef76402aa7bbb72c0b2e2dc0c8111"
AGENT = "quay.io/cilium/tetragon:v1.8.0@sha256:5ed9088a1582131d71b06c98e0d549a37a71ae63ab13aabefc7a47553c822a9d"
OPERATOR = ("quay.io/cilium/tetragon-operator:v1.8.0@sha256:"
            "af2b6f0a8609d66190f1d5bbdea38a160d5460f2ea416beea42a615aadd8b35a")
EXPORTER = ("quay.io/cilium/hubble-export-stdout:v1.1.1@sha256:"
            "cf701f96d1c8de30231792e35733e1ab07451e11751ef4f676f482836759da06")
AGENT_NS = "saf-fixture-observer"
POD = "saf-runner-marker"
POLICY = "saf-public-marker-read"
NETWORK_POLICY = "saf-owned-network-connect"
NETWORK_POD = "saf-owned-http-marker"
NETWORK_SERVICE = "saf-owned-http-marker"
NETWORK_PORT = 18080
MARKER = "/tmp/saf-fixture-public.txt"
OTHER = "/tmp/saf-fixture-control.txt"
SCOPE = (
    "A disposable Kind node with pinned Tetragon, namespace-scoped JSON export and a "
    "non-enforcing filename observation rule. Only the fixture runner and its public "
    "harmless markers are observed. Operator audit integration, network and credential "
    "coverage, event loss and downstream alert delivery require separate evidence."
)


def scoped(lab, namespace, obj):
    return lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(obj))


def install(lab, namespace):
    chart = lab.kubeconfig.parent / "tetragon-1.8.0.tgz"
    values = chart.with_name("tetragon-values.json")
    lab.command("curl", "-fLsS", "--max-time", "25", "-o", str(chart), CHART, timeout=30)
    if sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("The fixture's downloaded chart does not match its immutable expected checksum")
    values.write_text(json.dumps({
        "tetragon": {
            "image": {"override": AGENT},
            "enableK8sAPI": True,
            "exportAllowList": json.dumps({"namespace": [namespace],
                                          "event_set": ["PROCESS_EXEC", "PROCESS_KPROBE"]}),
        },
        "tetragonOperator": {"image": {"override": OPERATOR}},
        "export": {"stdout": {"image": {"override": EXPORTER}}},
        "crds": {"installMethod": "helm"},
    }))
    lab.command("helm", "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "upgrade", "--install", "tetragon", str(chart), "--namespace", AGENT_NS, "--create-namespace",
                "--values", str(values), "--wait", "--timeout", "100s", timeout=110)
    lab.kubectl("-n", AGENT_NS, "rollout", "status", "daemonset/tetragon", "--timeout=80s", timeout=90)


def sample(lab, namespace):
    start = f"printf 'public fixture marker\\n' > {MARKER} && printf 'owned comparison marker\\n' > {OTHER} && sleep 400"
    scoped(lab, namespace, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
                            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                     "containers": [container("marker", command=["sh", "-c", start])]}})
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=45s", timeout=55)


def events(lab, namespace):
    output = lab.kubectl("-n", AGENT_NS, "logs", "daemonset/tetragon", "-c", "export-stdout", "--tail=100")
    results = []
    for line in output.stdout.splitlines():
        if not line.startswith("{"):
            continue
        data = json.loads(line)
        key = next((kind for kind in ("process_exec", "process_kprobe") if kind in data), None)
        if key is None:
            continue
        record = data[key]
        pod = record.get("process", {}).get("pod", {})
        if pod.get("namespace") == namespace and pod.get("name") == POD:
            results.append((key, record))
    return results


def command(lab, namespace, path):
    result = lab.kubectl("-n", namespace, "exec", POD, "--", "/bin/busybox", "cat", path)
    expected = "public fixture marker" if path == MARKER else "owned comparison marker"
    if result.stdout.strip() != expected:
        lab.block("The read did not return the declared public fixture bytes")


def exec_ids(rows, path):
    return {record["process"]["exec_id"] for kind, record in rows if kind == "process_exec"
            and record["process"]["arguments"] == f"cat {path}"}


def filename_events(rows, ids):
    return [record for kind, record in rows
            if kind == "process_kprobe" and record.get("process", {}).get("exec_id") in ids
            and record.get("function_name") == "security_file_permission"
            and record.get("policy_name") == POLICY and MARKER in json.dumps(record.get("args", []))]


def connect_events(rows, namespace):
    matched = []
    for kind, record in rows:
        if (kind != "process_kprobe" or record.get("function_name") != "tcp_connect"
                or record.get("policy_name") != NETWORK_POLICY):
            continue
        process = record.get("process", {})
        pod = process.get("pod", {})
        if pod.get("namespace") != namespace or pod.get("name") != POD:
            continue
        args = record.get("args", [])
        sockets = [arg.get("sock_arg", {}) for arg in args if isinstance(arg, dict)]
        if any(sock.get("dport") == NETWORK_PORT for sock in sockets):
            matched.append(record)
    return matched


def wait_for(lab, namespace, match, reason):
    end = time.monotonic() + 24
    while time.monotonic() < end:
        snapshot = events(lab, namespace)
        if match(snapshot):
            return snapshot
        time.sleep(0.65)
    lab.block(reason)


def add_rule(lab, namespace):
    scoped(lab, namespace, {
        "apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicyNamespaced", "metadata": {"name": POLICY},
        "spec": {"kprobes": [{
            "call": "security_file_permission", "syscall": False, "return": True,
            "args": [{"index": 0, "type": "file"}, {"index": 1, "type": "int"}],
            "returnArg": {"index": 0, "type": "int"},
            "selectors": [{"matchArgs": [
                {"index": 0, "operator": "Equal", "values": [MARKER]},
                {"index": 1, "operator": "Equal", "values": ["4"]},
            ]}],
        }]},
    })
    end = time.monotonic() + 25
    while time.monotonic() < end:
        status = lab.kubectl("-n", AGENT_NS, "exec", "daemonset/tetragon", "-c", "tetragon",
                             "--", "tetra", "tracingpolicy", "list", allow_failure=True)
        if status.returncode == 0 and any(
            POLICY in line and "enabled" in line.lower() for line in status.stdout.splitlines()
        ):
            return
        time.sleep(0.5)
    lab.block("The namespaced public-marker observation policy did not become active")


def add_network_rule(lab, namespace):
    scoped(lab, namespace, {
        "apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicyNamespaced",
        "metadata": {"name": NETWORK_POLICY},
        "spec": {"kprobes": [{
            "call": "tcp_connect", "syscall": False,
            "args": [{"index": 0, "type": "sock"}],
        }]},
    })
    end = time.monotonic() + 25
    while time.monotonic() < end:
        status = lab.kubectl("-n", AGENT_NS, "exec", "daemonset/tetragon", "-c", "tetragon",
                             "--", "tetra", "tracingpolicy", "list", allow_failure=True)
        if status.returncode == 0 and any(
            NETWORK_POLICY in line and "enabled" in line.lower() for line in status.stdout.splitlines()
        ):
            return
        time.sleep(0.5)
    lab.block("The namespaced TCP-connect observation policy did not become active")


def network_fixture(lab, namespace):
    scoped(lab, namespace, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": NETWORK_POD, "labels": {"app": NETWORK_POD}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "containers": [container("http", command=["sh", "-c",
                     "printf 'owned network marker\\n' >/tmp/index.html; exec httpd -f -p "
                     f"{NETWORK_PORT} -h /tmp"])]},
    })
    scoped(lab, namespace, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": NETWORK_SERVICE},
        "spec": {"type": "ClusterIP", "selector": {"app": NETWORK_POD},
                 "ports": [{"name": "http", "port": NETWORK_PORT,
                            "targetPort": NETWORK_PORT, "protocol": "TCP"}]},
    })
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{NETWORK_POD}",
                "--timeout=45s", timeout=55)
    service_ip = lab.kubectl("-n", namespace, "get", "service", NETWORK_SERVICE,
                             "-o", "jsonpath={.spec.clusterIP}").stdout.strip()
    if not service_ip or service_ip.lower() == "none":
        lab.block("The fixture HTTP marker Service has no assigned ClusterIP")
    return service_ip


def network_request(lab, namespace, service_ip):
    result = lab.kubectl("-n", namespace, "exec", POD, "--", "/bin/busybox", "wget",
                         "-q", "-T", "4", "-O", "-",
                         f"http://{service_ip}:{NETWORK_PORT}/")
    if result.stdout.strip() != "owned network marker":
        lab.block("The owned in-cluster HTTP marker response was not exact")


def receiver_delivery(lab, accepted_record, unrelated_record, namespace):
    """Relay exact captured event bytes to an authenticated local fixture receiver."""
    token = secrets.token_urlsafe(32)
    alert_id = "SAF-BUILD-OWNED-MARKER-READ"
    accepted = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *args):
            # Never emit request headers or bearer material to stdout/stderr.
            return

        def _reply(self, status, obj):
            body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()):
                return self._reply(401, {"accepted": False})
            if self.path != "/events":
                return self._reply(404, {"accepted": False})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 262144:
                    return self._reply(413, {"accepted": False})
                payload = json.loads(self.rfile.read(size))
                record = payload["record"]
                pod = record.get("process", {}).get("pod", {})
                args = record.get("args", [])
                path_match = any(arg.get("file_arg", {}).get("path") == MARKER
                                 for arg in args if isinstance(arg, dict))
                valid = (payload.get("event_type") == "process_kprobe"
                         and record.get("function_name") == "security_file_permission"
                         and record.get("policy_name") == POLICY
                         and pod.get("namespace") == namespace and pod.get("name") == POD
                         and path_match)
                if not valid:
                    return self._reply(422, {"accepted": False})
                raw_digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                accepted.append({"alert_id": alert_id, "event_type": payload["event_type"], "policy": POLICY,
                                 "namespace": namespace, "pod": POD, "marker_match": True,
                                 "event_sha256": raw_digest})
                return self._reply(202, {"accepted": True})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                return self._reply(400, {"accepted": False})

        def do_GET(self):
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()):
                return self._reply(401, {"accepted": False})
            if self.path != "/state":
                return self._reply(404, {"accepted": False})
            return self._reply(200, {"accepted_count": len(accepted), "events": list(accepted)})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def call(method, route, auth, payload=None):
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=4)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")) if payload is not None else None
        headers = {"Authorization": "Bearer " + auth,
                   "Content-Type": "application/json"}
        try:
            connection.request(method, route, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read(16384))
        finally:
            connection.close()

    try:
        approved_payload = {"event_type": "process_kprobe", "record": accepted_record}
        denied_payload = {"event_type": "process_exec", "record": unrelated_record}
        altered = json.loads(json.dumps(approved_payload))
        for arg in altered["record"]["args"]:
            if arg.get("file_arg", {}).get("path") == MARKER:
                arg["file_arg"]["path"] = MARKER + ".different"
        bad_auth_status, bad_auth_body = call("POST", "/events", "wrong-fixture-token", approved_payload)
        accept_status, accept_body = call("POST", "/events", token, approved_payload)
        unrelated_status, unrelated_body = call("POST", "/events", token, denied_payload)
        wrong_path_status, _ = call("POST", "/events", token, altered)
        state_status, state = call("GET", "/state", token)
        denied_read_status, _ = call("GET", "/state", "wrong-fixture-token")
        expected_digest = sha256(json.dumps(approved_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        event = (state.get("events", [{}])[0] if state.get("events") else {})
        matched = (bad_auth_status == 401 and bad_auth_body.get("accepted") is False
                   and accept_status == 202 and accept_body.get("accepted") is True
                   and unrelated_status == 422 and unrelated_body.get("accepted") is False
                   and wrong_path_status == 422
                   and state_status == 200 and state.get("accepted_count") == 1
                   and len(state.get("events", [])) == 1 and event.get("event_sha256") == expected_digest
                   and event.get("marker_match") is True and event.get("alert_id") == alert_id
                   and denied_read_status == 401)
        lab.check("green", "The case receiver authenticates and accepts only the selected owned marker event",
                  matched, {"bad_auth_rejected": bad_auth_status == 401,
                            "selected_event_accepted": accept_status == 202,
                            "unselected_marker_rejected": unrelated_status == 422,
                            "changed_path_rejected": wrong_path_status == 422,
                            "readback_only_selected_event": state.get("accepted_count") == 1,
                            "unauthenticated_readback_rejected": denied_read_status == 401,
                            "exact_event_digest_read_back": event.get("event_sha256") == expected_digest,
                            "derived_alert_observed": event.get("alert_id") == alert_id,
                            "receiver_scope": "loopback-only ephemeral fixture; forwarding is case-runner modeled"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run(lab):
    namespace = "saf-observed-" + lab.cluster[-9:]
    lab.kubectl("create", "namespace", namespace)
    install(lab, namespace)
    sample(lab, namespace)
    command(lab, namespace, MARKER)
    before = wait_for(lab, namespace, lambda rows: exec_ids(rows, MARKER), "The fixture process did not reach export")
    old = exec_ids(before, MARKER)
    baseline_detected = bool(old) and not filename_events(before, old)
    lab.check("red", "Before the rule Tetragon sees fixture execution and lacks the marker-specific observation",
              baseline_detected, {"execution_visible": bool(old), "specific_file_observation_absent": baseline_detected})

    add_rule(lab, namespace)
    command(lab, namespace, MARKER)
    matched = wait_for(lab, namespace, lambda rows: filename_events(rows, exec_ids(rows, MARKER) - old),
                       "The active policy did not correlate the public marker access with its executing process")
    current = exec_ids(matched, MARKER) - old
    observed = filename_events(matched, current)
    lab.check("green", "The exact marker path is correlated with the same newly executed fixture process",
              bool(observed), {"marker_observed": bool(observed), "fixture_workload_identity_verified": bool(current)})

    command(lab, namespace, OTHER)
    compared = wait_for(lab, namespace, lambda rows: exec_ids(rows, OTHER), "The unselected marker command was absent")
    unrelated = exec_ids(compared, OTHER)
    omitted = bool(unrelated) and not filename_events(compared, unrelated)
    lab.check("positive", "The other harmless read remains visible as execution without a matching file observation",
              omitted, {"comparison_execution_visible": bool(unrelated), "marker_specific_filter_preserved": omitted})

    service_ip = network_fixture(lab, namespace)
    network_request(lab, namespace, service_ip)
    baseline_connections = connect_events(events(lab, namespace), namespace)
    red_absent = not baseline_connections
    add_network_rule(lab, namespace)
    network_request(lab, namespace, service_ip)
    observed_connections = wait_for(
        lab, namespace, lambda rows: bool(connect_events(rows, namespace)),
        "The selected owned TCP connection did not reach the Tetragon event export",
    )
    selected = connect_events(observed_connections, namespace)
    fields_ok = bool(selected) and all(
        any(isinstance(arg, dict) and arg.get("sock_arg", {}).get("dport") == NETWORK_PORT
            for arg in record.get("args", [])) for record in selected
    )
    lab.check("green", "The namespaced Tetragon policy adds an attributed event for the owned TCP marker request",
              red_absent and fields_ok,
              {"tcp_event_absent_before_policy": red_absent,
               "tcp_event_attributed_to_fixture_pod": bool(selected),
               "fixed_owned_listener_port_observed": fields_ok,
               "exact_http_marker_response_verified": True})
    (lab.evidence / "fixture-observation.json").write_text(json.dumps({
        "chart_sha256": CHART_HASH, "before_exec_ids": sorted(old), "matched_exec_ids": sorted(current),
        "observations": observed,
    }, indent=2, sort_keys=True) + "\n")
    # The receiver gets the exact Tetragon record selected above and the real
    # process-only comparator event; it does not synthesize either source event.
    receiver_delivery(lab, observed[0], next((record for kind, record in compared
                       if kind == "process_exec" and record.get("process", {}).get("arguments") == f"cat {OTHER}"), {}),
                      namespace)
