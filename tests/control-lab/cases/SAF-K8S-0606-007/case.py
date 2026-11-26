"""Observe the owned runner's harmless command and public marker access."""
from hashlib import sha256
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import json
from pathlib import Path
import re
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
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
MARKER = "/tmp/saf-fixture-public.txt"
OTHER = "/tmp/saf-fixture-control.txt"
SCOPE = (
    "A disposable Kind node with pinned Tetragon, namespace-scoped JSON export and a "
    "non-enforcing filename observation rule. Only the fixture runner and its public "
    "harmless markers are observed. Operator audit integration, network and credential "
    "coverage, event loss and downstream alert delivery require separate evidence. A bounded "
    "case-owned exporter reads one exact Tetragon Pod log and submits the selected event over "
    "fixture mTLS to an API-backed receipt in the same disposable cluster."
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


def read_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def tetragon_pod(lab):
    pods = read_json(lab, "-n", AGENT_NS, "get", "pods")["items"]
    eligible = []
    for pod in pods:
        meta = pod.get("metadata", {})
        labels = meta.get("labels", {})
        owners = meta.get("ownerReferences", [])
        agent = (labels.get("app.kubernetes.io/name") == "tetragon"
                 or any(owner.get("kind") == "DaemonSet" and owner.get("name") == "tetragon"
                        for owner in owners))
        status = pod.get("status", {})
        ready = (status.get("phase") == "Running" and any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in status.get("conditions", [])))
        names = {container.get("name") for container in pod.get("spec", {}).get("containers", [])}
        if agent and ready and "export-stdout" in names:
            eligible.append(pod)
    if len(eligible) != 1:
        lab.block("Expected exactly one Ready Tetragon JSON exporter Pod on the disposable node")
    other_ready = [pod for pod in pods if pod["metadata"]["name"] != eligible[0]["metadata"]["name"]
                   and pod.get("status", {}).get("phase") == "Running"
                   and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                           for condition in pod.get("status", {}).get("conditions", []))]
    if not other_ready:
        lab.block("Expected a second Ready case-owned Tetragon namespace Pod for the denied log comparator")
    return eligible[0], other_ready[0]


def issue_transport_material(lab, namespace):
    root = lab.kubeconfig.parent
    ca_key, ca_cert = root / "export-ca.key", root / "export-ca.crt"
    server_key, server_csr, server_cert = root / "receiver.key", root / "receiver.csr", root / "receiver.crt"
    client_key, client_csr, client_cert = root / "client.key", root / "client.csr", root / "client.crt"
    server_ext, client_ext = root / "server.ext", root / "client.ext"
    server_dns = f"saf-event-receiver.{namespace}.svc.cluster.local"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=saf-0606-007-fixture-ca", "-keyout", str(ca_key), "-out", str(ca_cert),
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", timeout=45)
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                f"/CN={server_dns}", "-keyout", str(server_key), "-out", str(server_csr), timeout=45)
    server_ext.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        f"subjectAltName=DNS:saf-event-receiver.{namespace}.svc,DNS:{server_dns}\n")
    lab.command("openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert), "-days", "1",
                "-sha256", "-extfile", str(server_ext), timeout=45)
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                "/CN=saf-event-exporter", "-keyout", str(client_key), "-out", str(client_csr), timeout=45)
    client_ext.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        "subjectAltName=URI:spiffe://saf.example/0606-007/exporter\n")
    lab.command("openssl", "x509", "-req", "-in", str(client_csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(client_cert), "-days", "1",
                "-sha256", "-extfile", str(client_ext), timeout=45)
    for path in (ca_key, server_key, client_key):
        path.chmod(0o600)
    lab.kubectl("-n", namespace, "create", "secret", "generic", "saf-event-receiver-tls",
                f"--from-file=tls.crt={server_cert}", f"--from-file=tls.key={server_key}",
                f"--from-file=ca.crt={ca_cert}", "-o", "name")
    lab.kubectl("-n", namespace, "create", "secret", "generic", "saf-event-exporter-tls",
                f"--from-file=tls.crt={client_cert}", f"--from-file=tls.key={client_key}",
                f"--from-file=ca.crt={ca_cert}", "-o", "name")
def workload_event_export(lab, namespace, expected_event_digest):
    agent, other = tetragon_pod(lab)
    agent_name = agent["metadata"]["name"]
    other_name = other["metadata"]["name"]
    exporter_sa, receiver_sa = "saf-event-exporter", "saf-event-receiver"
    issue_transport_material(lab, namespace)
    for name in (exporter_sa, receiver_sa):
        scoped(lab, namespace, {"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": namespace},
                    "automountServiceAccountToken": True})
    scoped(lab, AGENT_NS, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "saf-export-selected-tetragon-log", "namespace": AGENT_NS},
                "rules": [{"apiGroups": [""], "resources": ["pods/log"],
                           "resourceNames": [agent_name], "verbs": ["get"]}]})
    scoped(lab, AGENT_NS, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "saf-export-selected-tetragon-log", "namespace": AGENT_NS},
                "subjects": [{"kind": "ServiceAccount", "name": exporter_sa, "namespace": namespace}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "saf-export-selected-tetragon-log"}})
    scoped(lab, namespace, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "saf-write-event-receipt", "namespace": namespace},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]})
    scoped(lab, namespace, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "saf-write-event-receipt", "namespace": namespace},
                "subjects": [{"kind": "ServiceAccount", "name": receiver_sa, "namespace": namespace}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "saf-write-event-receipt"}})
    receiver_user = f"system:serviceaccount:{namespace}:{receiver_sa}"
    policy_expr = (
        f'request.userInfo.username != "{receiver_user}" || '
        '(object.metadata.name == "saf-tetragon-event-receipt" && object.immutable == true && '
        'object.metadata.labels["saf.example/tetragon-receipt"] == "true" && '
        'object.data["receipt.json"] != "")'
    )
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": "saf-tetragon-receipt-writer"},
                "spec": {"matchConstraints": {"resourceRules": [{"apiGroups": [""],
                    "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["configmaps"]}]},
                    "validations": [{"expression": policy_expr,
                        "message": "receiver may create only the immutable fixture event receipt"}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": "saf-tetragon-receipt-writer"},
                "spec": {"policyName": "saf-tetragon-receipt-writer", "validationActions": ["Deny"],
                          "matchResources": {"namespaceSelector": {"matchLabels": {
                              "kubernetes.io/metadata.name": namespace}}}}})
    for name, script in (("saf-event-receiver-code", "receiver.py"),
                         ("saf-event-exporter-code", "exporter.py")):
        scoped(lab, namespace, {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "namespace": namespace}, "immutable": True,
                    "data": {script: (HERE / script).read_text(encoding="utf-8")}})
    pod_security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                    "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
    container_security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                          "capabilities": {"drop": ["ALL"]}}
    scoped(lab, namespace, {"apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-event-receiver", "namespace": namespace,
                     "labels": {"app": "saf-event-receiver"}},
        "spec": {"restartPolicy": "Never", "serviceAccountName": receiver_sa,
            "securityContext": pod_security,
            "containers": [{"name": "receiver", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "/fixture/receiver.py"],
                "env": [{"name": "FIXTURE_NAMESPACE", "value": namespace},
                        {"name": "FIXTURE_POD", "value": POD}, {"name": "FIXTURE_POLICY", "value": POLICY},
                        {"name": "FIXTURE_PATH", "value": MARKER}],
                "ports": [{"name": "https", "containerPort": 8443}],
                "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                 {"name": "tls", "mountPath": "/tls", "readOnly": True}],
                "readinessProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 2,
                                    "failureThreshold": 15},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "securityContext": container_security}],
            "volumes": [{"name": "code", "configMap": {"name": "saf-event-receiver-code"}},
                        {"name": "tls", "secret": {"secretName": "saf-event-receiver-tls",
                                                       "defaultMode": 288}}]}})
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/saf-event-receiver",
                "--timeout=30s", timeout=40)
    scoped(lab, namespace, {"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "saf-event-receiver", "namespace": namespace},
                "spec": {"type": "ClusterIP", "selector": {"app": "saf-event-receiver"},
                         "ports": [{"name": "https", "port": 8443, "targetPort": "https",
                                    "protocol": "TCP"}]}})

    job = {"apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "saf-event-exporter", "namespace": namespace},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60,
            "template": {"metadata": {"labels": {"app": "saf-event-exporter"}},
                "spec": {"restartPolicy": "Never", "serviceAccountName": exporter_sa,
                    "securityContext": pod_security,
                    "containers": [{"name": "exporter", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent", "command": ["python", "/fixture/exporter.py"],
                        "env": [{"name": "AGENT_NAMESPACE", "value": AGENT_NS},
                                {"name": "AGENT_POD", "value": agent_name},
                                {"name": "OTHER_AGENT_POD", "value": other_name},
                                {"name": "FIXTURE_NAMESPACE", "value": namespace},
                                {"name": "FIXTURE_POD", "value": POD},
                                {"name": "FIXTURE_POLICY", "value": POLICY},
                                {"name": "FIXTURE_PATH", "value": MARKER},
                                {"name": "EXPECTED_EVENT_DIGEST", "value": expected_event_digest},
                                {"name": "RECEIVER_URL", "value": f"https://saf-event-receiver.{namespace}.svc.cluster.local:8443"}],
                        "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                         {"name": "tls", "mountPath": "/tls", "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                      "limits": {"cpu": "100m", "memory": "96Mi"}},
                        "securityContext": container_security}],
                    "volumes": [{"name": "code", "configMap": {"name": "saf-event-exporter-code"}},
                                {"name": "tls", "secret": {"secretName": "saf-event-exporter-tls",
                                                               "defaultMode": 288}}]}}}}
    scoped(lab, namespace, job)
    completed = lab.kubectl("-n", namespace, "wait", "--for=condition=complete", "job/saf-event-exporter",
                             "--timeout=60s", timeout=70, allow_failure=True)
    if completed.returncode:
        lab.kubectl("-n", namespace, "logs", "job/saf-event-exporter", allow_failure=True)
        lab.block("The exact authenticated Tetragon exporter Job did not succeed")
    job_pod = read_json(lab, "-n", namespace, "get", "pods", "-l", "job-name=saf-event-exporter")["items"]
    logs = lab.kubectl("-n", namespace, "logs", "job/saf-event-exporter").stdout.strip().splitlines()
    result = json.loads(logs[-1]) if logs else {}
    cm = read_json(lab, "-n", namespace, "get", "configmap", "saf-tetragon-event-receipt")
    receipt = json.loads(cm.get("data", {}).get("receipt.json", "{}"))
    receiver_pod = read_json(lab, "-n", namespace, "get", "pod", "saf-event-receiver")
    process_ok = (len(job_pod) == 1
                  and job_pod[0].get("spec", {}).get("serviceAccountName") == exporter_sa
                  and job_pod[0].get("status", {}).get("phase") == "Succeeded")
    observed = {
        "named_agent_source_read": result.get("source_read") is True,
        "unauthorized_log_source_denied": result.get("other_source_denied") is True,
        "one_correlated_event_exported": result.get("exactly_one_event") is True,
        "no_client_certificate_refused": result.get("client_certificate_required") is True,
        "receiver_service_name_verified": result.get("server_name_verified") is True,
        "mTLS_delivery_succeeded": result.get("authenticated_delivery") is True,
        "receiver_api_writer_identity_scoped": (
            receiver_pod.get("spec", {}).get("serviceAccountName") == receiver_sa),
        "exporter_job_succeeded_as_scoped_identity": process_ok,
        "receipt_is_immutable": cm.get("immutable") is True,
        "receipt_writer_label_present": (
            cm.get("metadata", {}).get("labels", {}).get("saf.example/source") == "case-owned-exporter"),
        "receipt_digest_matches_export": (
            bool(re.fullmatch(r"[0-9a-f]{64}", receipt.get("event_sha256", "")))
            and receipt.get("event_sha256") == result.get("event_sha256") == expected_event_digest),
        "receipt_is_exact_selected_event": (
            receipt.get("accepted") is True
            and receipt.get("event_type") == "process_kprobe"
            and receipt.get("policy_match") is True
            and receipt.get("path_match") is True
            and receipt.get("fixture_process_correlated") is True
            and receipt.get("fixture_pod_match") is True
            and receipt.get("authenticated_client") is True
            and receipt.get("client_identity") == "fixture-exporter"),
    }
    lab.check("green", "A case-owned workload exports the selected Tetragon event over mTLS and the independent API read returns its immutable receipt",
              all(observed.values()), observed)


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
    event_bytes = json.dumps(observed[0], sort_keys=True, separators=(",", ":")).encode()
    workload_event_export(lab, namespace, sha256(event_bytes).hexdigest())
