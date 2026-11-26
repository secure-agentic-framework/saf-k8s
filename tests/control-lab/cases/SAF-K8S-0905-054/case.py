"""Check scoped downloads of inert model JSON under Kubernetes NetworkPolicy."""
from hashlib import sha256
from ipaddress import IPv4Address
import json
import time
from urllib.parse import quote

from fixtures import BUSYBOX_IMAGE, container, pod

PROTECTED = "saf-model-protected"
CONTROL = "saf-model-control"
PROXY = "saf-model-proxy"
HUB = "saf-model-hub"
APPROVED_UPSTREAM = "saf-model-approved-upstream"
UNAPPROVED_UPSTREAM = "saf-model-unapproved-upstream"
PORT = 8080
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
APPROVED = '{"model":"approved-proxy","weight":2}'
HUB_ARTIFACT = '{"model":"direct-hub","weight":3}'
EXTERNAL = '{"model":"external-fixture-hub","weight":4}'
APPROVED_UPSTREAM_BYTES = '{"model":"approved-owned-upstream","weight":5}'
UNAPPROVED_UPSTREAM_BYTES = '{"model":"unapproved-owned-upstream","weight":6}'
APPROVED_SOURCE_URI = "fixture://approved-owned-model-source"
UNAPPROVED_SOURCE_URI = "fixture://unapproved-owned-model-source"
APPROVED_UPSTREAM_URL = (
    f"http://models.{APPROVED_UPSTREAM}.svc.cluster.local:{PORT}/model.json"
)
SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster with bundled kindnet compares the same "
    "protected client's HTTP model downloads before and after a native NetworkPolicy. "
    "The policy allows CoreDNS and the exact labeled proxy namespace and Pods. The case "
    "checks in-cluster Service and direct Pod IP paths and a case-owned off-cluster Docker "
    "peer on an internal bridge. The unselected namespace can still reach denied targets. "
    "A supplemental application proxy maps one exact source identifier to fixed bytes from "
    "an owned in-cluster upstream and refuses a different owned source before fetching it. "
    "These application source rules are separate from NetworkPolicy selectors. The synthetic "
    "JSON requests use TCP/8080. Production telemetry, public-hub and domain identity, "
    "provider paths and non-Pod consumers are open."
)


UPSTREAM_SERVER_CODE = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys
body = sys.argv[1].encode()
fetches = 0
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global fetches
        if self.path == "/model.json":
            fetches += 1
            payload, status = body, 200
        elif self.path == "/_fixture_count":
            payload, status = json.dumps({"model_fetches": fetches}).encode(), 200
        else:
            payload, status = b"not-found", 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, fmt, *args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


PROXY_SERVER_CODE = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener
import sys

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None

allowed_source, upstream_url, static_body = sys.argv[1], sys.argv[2], sys.argv[3].encode()
owned_upstream = build_opener(ProxyHandler({}), NoRedirect())

class Handler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/model.json":
            self.send_body(200, static_body)
            return
        if parsed.path != "/fetch":
            self.send_body(404, b"not-found", "text/plain")
            return
        source = parse_qs(parsed.query).get("source", [""])[0]
        if source != allowed_source:
            self.send_body(403, b"source-not-approved", "text/plain")
            return
        try:
            with owned_upstream.open(upstream_url, timeout=3) as response:
                body = response.read(4097)
            if len(body) > 4096:
                self.send_body(502, b"upstream-size-limit", "text/plain")
            else:
                self.send_body(200, body)
        except Exception:
            self.send_body(502, b"upstream-unavailable", "text/plain")
    def log_message(self, fmt, *args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


PROXY_PROBE_CODE = r'''
import hashlib, json, sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
try:
    with urlopen(sys.argv[1], timeout=5) as response:
        status, body = response.status, response.read(4097)
except HTTPError as error:
    status, body = error.code, error.read(4097)
except URLError:
    status, body = 0, b""
print(json.dumps({"status": status, "body_sha256": hashlib.sha256(body).hexdigest(),
                  "body_size": len(body)}))
'''


def _create(lab, ns, resource):
    return json.loads(lab.kubectl("-n", ns, "create", "-f", "-", "-o", "json",
                                 payload=json.dumps(resource)).stdout)


def _get(lab, ns, resource, name):
    return json.loads(lab.kubectl("-n", ns, "get", resource, name, "-o", "json").stdout)


def _serve(body):
    return ["sh", "-ec", f"printf '%s' '{body}' >/tmp/model.json; exec httpd -f -p {PORT} -h /tmp"]


def _start_pod(lab, ns, name, role, command, *, listener=False):
    probe = {"readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1}} if listener else {}
    c = container("fixture", command=command,
                  resources={"requests": {"cpu": "10m", "memory": "12Mi"},
                             "limits": {"cpu": "100m", "memory": "32Mi"}}, **probe)
    resource = pod(name, [c], automountServiceAccountToken=False)
    resource["metadata"]["labels"] = {"app": role}
    _create(lab, ns, resource)


def _start_python_pod(lab, ns, name, role, code, args=(), *, listener=False):
    probe = {"readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1}} if listener else {}
    c = container("fixture", image=PYTHON_IMAGE,
                  command=["python", "-u", "-c", code, *args],
                  resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                             "limits": {"cpu": "150m", "memory": "96Mi"}}, **probe)
    resource = pod(name, [c], automountServiceAccountToken=False)
    resource["metadata"]["labels"] = {"app": role}
    _create(lab, ns, resource)


def _wait(lab, ns, name):
    lab.kubectl("-n", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=70s", timeout=80)
    return _get(lab, ns, "pod", name)


def _service(lab, ns, role):
    svc = _create(lab, ns, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "models"},
                            "spec": {"selector": {"app": role},
                                     "ports": [{"port": PORT, "targetPort": PORT}]}})
    return svc["spec"]["clusterIP"]


def _url(target):
    return f"http://{target}:{PORT}/model.json"


def _request(lab, ns, host, exact):
    r = lab.kubectl("-n", ns, "exec", "client", "--", "wget", "-qT", "2", "-O-", _url(host),
                    timeout=12, allow_failure=True)
    if r.returncode == 0:
        if r.stdout != exact:
            lab.block("Owned model listener served different fixture bytes")
        return True
    if any(reason in r.stderr.lower() for reason in ("timed out", "timeout", "operation timed out")):
        return False
    lab.block(f"Model request failed outside the expected timeout: {r.stderr.strip()}")


def _check(lab, phase, claim, ns, host, model, allowed):
    deadline = time.monotonic() + 26
    consecutive = 0
    reachable = None
    while consecutive < 2 and time.monotonic() < deadline:
        reachable = _request(lab, ns, host, model)
        consecutive = consecutive + 1 if reachable == allowed else 0
        if consecutive < 2:
            time.sleep(0.25)
    lab.check(phase, claim, consecutive == 2,
              {"source_namespace": ns, "reachable": reachable, "consecutive_observations": consecutive,
               "model_sha256": sha256(model.encode()).hexdigest() if reachable else None})


def _resolve(lab, host, expected):
    result = lab.kubectl("-n", PROTECTED, "exec", "client", "--", "nslookup",
                         "-timeout=2", "-retry=1", host, timeout=12, allow_failure=True)
    return result.returncode == 0 and expected in result.stdout.split()


def _proxy_fetch(lab, source):
    url = (f"http://models.{PROXY}.svc.cluster.local:{PORT}/fetch"
           f"?source={quote(source, safe='')}")
    result = lab.kubectl("-n", PROTECTED, "exec", "proxy-source-probe", "--",
                         "python", "-c", PROXY_PROBE_CODE, url, timeout=15)
    return json.loads(result.stdout)


def _source_count(lab, namespace):
    url = f"http://models.{namespace}.svc.cluster.local:{PORT}/_fixture_count"
    result = lab.kubectl("-n", CONTROL, "exec", "client", "--", "wget",
                         "-qT", "2", "-O-", url, timeout=12)
    return json.loads(result.stdout)["model_fetches"]


def _proxy_source_allowlist_check(lab, uid):
    probe = _start_python_pod(
        lab, PROTECTED, "proxy-source-probe", "proxy-source-probe",
        "import time; time.sleep(900)")
    del probe
    _wait(lab, PROTECTED, "proxy-source-probe")
    cleanup_ok = False
    try:
        approved_host = f"models.{APPROVED_UPSTREAM}.svc.cluster.local"
        unapproved_host = f"models.{UNAPPROVED_UPSTREAM}.svc.cluster.local"
        approved_control_live = _request(
            lab, CONTROL, approved_host, APPROVED_UPSTREAM_BYTES)
        unapproved_control_live = _request(
            lab, CONTROL, unapproved_host, UNAPPROVED_UPSTREAM_BYTES)
        approved_before = _source_count(lab, APPROVED_UPSTREAM)
        unapproved_before = _source_count(lab, UNAPPROVED_UPSTREAM)

        # The protected workload cannot reach upstreams directly; it can reach only the proxy.
        protected_direct_blocked = not _request(
            lab, PROTECTED, approved_host, APPROVED_UPSTREAM_BYTES)
        approved_result = _proxy_fetch(lab, APPROVED_SOURCE_URI)
        unapproved_result = _proxy_fetch(lab, UNAPPROVED_SOURCE_URI)

        approved_after = _source_count(lab, APPROVED_UPSTREAM)
        unapproved_after = _source_count(lab, UNAPPROVED_UPSTREAM)
        proxy_np = json.loads(lab.kubectl(
            "-n", PROXY, "get", "networkpolicies", "-o", "json").stdout)
        proxy_has_no_egress_np = len(proxy_np.get("items", [])) == 0
        unchanged_client = _get(lab, PROTECTED, "pod", "client")["metadata"]["uid"] == uid

        allowed_response = (
            approved_result.get("status") == 200
            and approved_result.get("body_sha256") == sha256(
                APPROVED_UPSTREAM_BYTES.encode()).hexdigest()
            and approved_result.get("body_size") == len(APPROVED_UPSTREAM_BYTES))
        refused_response = (
            unapproved_result.get("status") == 403
            and unapproved_result.get("body_sha256") == sha256(
                b"source-not-approved").hexdigest())
        counts_match = (approved_after == approved_before + 1
                        and unapproved_after == unapproved_before)
        evidence = {
            "approved_source_directly_live_from_control_namespace": approved_control_live,
            "unapproved_source_directly_live_from_control_namespace": unapproved_control_live,
            "protected_client_direct_source_blocked": protected_direct_blocked,
            "approved_source_returned_exact_upstream_digest": allowed_response,
            "separately_named_unapproved_source_refused_403": refused_response,
            "approved_upstream_fetch_count_incremented_once": approved_after == approved_before + 1,
            "unapproved_upstream_fetch_count_unchanged": unapproved_after == unapproved_before,
            "proxy_namespace_has_no_networkpolicy": proxy_has_no_egress_np,
            "protected_client_identity_unchanged": unchanged_client,
            "approved_fetch_count_before": approved_before,
            "approved_fetch_count_after": approved_after,
            "unapproved_fetch_count_before": unapproved_before,
            "unapproved_fetch_count_after": unapproved_after,
        }
        passed = all([
            approved_control_live, unapproved_control_live, protected_direct_blocked,
            allowed_response, refused_response, counts_match, proxy_has_no_egress_np,
            unchanged_client,
        ])
    finally:
        result = lab.kubectl("-n", PROTECTED, "delete", "pod", "proxy-source-probe",
                             "--ignore-not-found=true", "--wait=true",
                             allow_failure=True)
        cleanup_ok = result.returncode == 0
    evidence["probe_cleanup_succeeded"] = cleanup_ok
    evidence["passed"] = passed and cleanup_ok
    (lab.evidence / "proxy-source-allowlist.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lab.check("positive",
              "The approved proxy fetches only its exact owned upstream and refuses the separately named source",
              evidence["passed"],
              {key: value for key, value in evidence.items()
               if key not in {"approved_fetch_count_before", "approved_fetch_count_after",
                              "unapproved_fetch_count_before", "unapproved_fetch_count_after"}})


def _policy(lab):
    def targets(ns, key, value, ports):
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                        "podSelector": {"matchLabels": {key: value}}}],
                "ports": [{"protocol": protocol, "port": port} for protocol, port in ports]}
    return _create(lab, PROTECTED, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "model-downloads"},
        "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                 "egress": [targets(PROXY, "app", "approved-proxy", [("TCP", PORT)]),
                            targets("kube-system", "k8s-app", "kube-dns", [("UDP", 53), ("TCP", 53)])]},
    })


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    for ns in (PROTECTED, CONTROL, PROXY, HUB, APPROVED_UPSTREAM, UNAPPROVED_UPSTREAM):
        lab.kubectl("create", "namespace", ns)
    _start_python_pod(
        lab, PROXY, "models", "approved-proxy", PROXY_SERVER_CODE,
        (APPROVED_SOURCE_URI, APPROVED_UPSTREAM_URL, APPROVED), listener=True)
    _start_pod(lab, HUB, "models", "direct-hub", _serve(HUB_ARTIFACT), listener=True)
    _start_python_pod(
        lab, APPROVED_UPSTREAM, "models", "approved-source", UPSTREAM_SERVER_CODE,
        (APPROVED_UPSTREAM_BYTES,), listener=True)
    _start_python_pod(
        lab, UNAPPROVED_UPSTREAM, "models", "unapproved-source", UPSTREAM_SERVER_CODE,
        (UNAPPROVED_UPSTREAM_BYTES,), listener=True)
    for ns in (PROTECTED, CONTROL):
        _start_pod(lab, ns, "client", "client", ["sleep", "900"])
    uid = _wait(lab, PROTECTED, "client")["metadata"]["uid"]
    _wait(lab, CONTROL, "client")
    _wait(lab, PROXY, "models")
    _wait(lab, APPROVED_UPSTREAM, "models")
    _wait(lab, UNAPPROVED_UPSTREAM, "models")
    hub_ip = str(IPv4Address(_wait(lab, HUB, "models")["status"]["podIP"]))
    approved_ip = _service(lab, PROXY, "approved-proxy")
    hub_service_ip = _service(lab, HUB, "direct-hub")
    for namespace, role in ((APPROVED_UPSTREAM, "approved-source"),
                            (UNAPPROVED_UPSTREAM, "unapproved-source")):
        service_ip = _service(lab, namespace, role)
        host = f"models.{namespace}.svc.cluster.local"
        deadline = time.monotonic() + 15
        while not _resolve(lab, host, service_ip):
            if time.monotonic() >= deadline:
                lab.block("The case-owned upstream Service did not resolve")
            time.sleep(0.25)
    proxy_host = f"models.{PROXY}.svc.cluster.local"
    hub_host = f"models.{HUB}.svc.cluster.local"

    network = f"{lab.cluster}-private-model-source"
    node = f"{lab.cluster}-control-plane"
    external = f"{lab.cluster}-direct-model-hub"
    connected = running = False
    lab.command("docker", "network", "create", "--internal", network)
    try:
        lab.command("docker", "network", "connect", network, node)
        connected = True
        lab.command("docker", "run", "--rm", "--detach", "--name", external,
                    "--network", network, "--user=65534:65534", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", BUSYBOX_IMAGE, *_serve(EXTERNAL))
        running = True
        inspect = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        outside = str(IPv4Address(lab.command("docker", "inspect", "--format", inspect, external).stdout.strip()))
        for label, host, model in (("proxy service", proxy_host, APPROVED),
                                   ("in-cluster direct hub service", hub_host, HUB_ARTIFACT),
                                   ("in-cluster hub Pod IP", hub_ip, HUB_ARTIFACT),
                                   ("off-cluster private hub", outside, EXTERNAL)):
            _check(lab, "red", f"Before enforcement the protected client downloads from the {label}",
                   PROTECTED, host, model, True)
        policy = _policy(lab)
        _check(lab, "green", "Protected namespace denies the same direct hub through its Service",
               PROTECTED, hub_host, HUB_ARTIFACT, False)
        _check(lab, "green", "Protected namespace denies the same hub Pod IP",
               PROTECTED, hub_ip, HUB_ARTIFACT, False)
        _check(lab, "green", "Protected namespace denies the same off-cluster hub IP",
               PROTECTED, outside, EXTERNAL, False)
        _check(lab, "positive", "The same protected client retrieves exact approved model bytes through its proxy",
               PROTECTED, proxy_host, APPROVED, True)
        _check(lab, "positive", "The in-cluster hub remains live from the unselected namespace",
               CONTROL, hub_host, HUB_ARTIFACT, True)
        _check(lab, "positive", "The off-cluster fixture remains live from the unselected namespace",
               CONTROL, outside, EXTERNAL, True)
        resolved = {"proxy": _resolve(lab, proxy_host, approved_ip), "hub": _resolve(lab, hub_host, hub_service_ip)}
        same_uid = _get(lab, PROTECTED, "pod", "client")["metadata"]["uid"] == uid
        lab.check("positive", "Both Kubernetes DNS records still resolve and the protected client is unchanged",
                  all(resolved.values()) and same_uid, {"services_resolve": resolved, "same_pod_uid": same_uid})
        path = lab.evidence / "model-source-egress.json"
        path.write_text(json.dumps({"network_policy": policy["spec"], "protected_pod_uid": uid,
                                    "checks": lab.checks}, indent=2) + "\n")
    finally:
        if running:
            lab.command("docker", "rm", "--force", external)
        if connected:
            lab.command("docker", "network", "disconnect", network, node)
        lab.command("docker", "network", "rm", network)
    _proxy_source_allowlist_check(lab, uid)
