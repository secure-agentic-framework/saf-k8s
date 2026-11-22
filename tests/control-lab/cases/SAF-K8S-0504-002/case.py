"""Bounded Istio mTLS, identity authorization, metrics, and trace case."""
from hashlib import sha256
import json
import platform
import tarfile
import time
from pathlib import Path


CONTROL_ID = "SAF-K8S-0504-002"
ISTIO_VERSION = "1.32.0"
ISTIO_RELEASE_SHA256 = {
    "Linux-x86_64": "b9cc0d427e2742b63ade28e15332a4b5da37ebf2d777a25ba22cc91bbfd51fbf",
    "Linux-arm64": "76f220746c75b6b0098d752da941ed91afc4e0cfd6722b853172d764fb6c2173",
    "Darwin-arm64": "1d9a82445c2395f85ce3a165dc90e182ad4e52214f85c18e93db274fd6d82fbb",
    "Darwin-x86_64": "803f30507ba687f88e10ea9b6736dfb77fcc3c66c1d3ce8dc71420bfcfe27d6c",
}
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0504-002"
SOURCE_NS = f"{NAMESPACE}-clients"
DEST_NS = f"{NAMESPACE}-services"
BACKEND = f"{NAMESPACE}-backend"
ALLOWED_CLIENT = f"{NAMESPACE}-approved-client"
DENIED_CLIENT = f"{NAMESPACE}-comparison-client"
PLAIN_CLIENT = f"{NAMESPACE}-unmeshed-client"
PORT = 8080
PATH = "/owned/request"
SCOPE = (
    "Fresh disposable Kubernetes v1.36.1 Kind cluster with pinned Istio 1.32.0 "
    "sidecar mode. Two case-owned clients with distinct Kubernetes service accounts "
    "send the same ordinary HTTP GET to one case-owned backend. The case compares "
    "plain baseline behavior with injected workload behavior, verifies automatic "
    "mTLS through the backend's observed XFCC SPIFFE identity, then applies one exact "
    "service-account AuthorizationPolicy and checks allowed 200 versus denied 403. "
    "It queries backend proxy request metrics and Jaeger for one generated trace. "
    "Only these fixtures and this in-cluster request are in scope."
)


def kubectl(lab, *args, timeout=45, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(5, timeout - 5)}s", *args, timeout=timeout, **kwargs,
    )


def json_resource(lab, resource):
    kubectl(lab, "apply", "-f", "-", payload=json.dumps(resource))


def wait_ready(lab, namespace, pod_name, timeout=180):
    kubectl(lab, "-n", namespace, "wait", "--for=condition=Ready", f"pod/{pod_name}",
            f"--timeout={timeout}s", timeout=timeout + 10)


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
        wanted = (root + "bin/istioctl", root + "samples/addons/jaeger.yaml")
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
    return istioctl_path, workdir / f"istio-{ISTIO_VERSION}"


def install_mesh(lab, istioctl, release_dir, workdir):
    # Install the discovery and injection components. Add the trace receiver separately.
    config = workdir / "istio-config.yaml"
    config.write_text("""apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  profile: minimal
  meshConfig:
    enableTracing: true
    defaultConfig:
      tracing: {}
    extensionProviders:
    - name: jaeger
      opentelemetry:
        service: jaeger-collector.istio-system.svc.cluster.local
        port: 4317
""")
    lab.command(str(istioctl), "install", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "-f", str(config), "-y", timeout=360)
    kubectl(lab, "-n", "istio-system", "rollout", "status", "deployment/istiod",
            "--timeout=180s", timeout=190)
    addon = release_dir / "samples" / "addons" / "jaeger.yaml"
    if not addon.is_file():
        lab.block("Digest-checked release archive did not contain the Jaeger sample")
    kubectl(lab, "apply", "-f", str(addon), timeout=120)
    kubectl(lab, "-n", "istio-system", "rollout", "status", "deployment/jaeger",
            "--timeout=180s", timeout=190)
    lab.check("positive", f"Istio {ISTIO_VERSION} and Jaeger sample are ready",
              True, {"istio_version": ISTIO_VERSION, "archive_sha256_verified": True,
                     "kubernetes_version": "v1.36.1"})


def namespace(name, inject=False):
    labels = {"saf-k8s.example/0504-002-fixture": "true"}
    if inject:
        labels["istio-injection"] = "enabled"
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels}}


def service_account(name, ns):
    return {"apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": ns}, "automountServiceAccountToken": False}


def pod(name, ns, sa, labels, command):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {
            "serviceAccountName": sa, "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "app", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", command],
                "ports": ([{"name": "http", "containerPort": PORT}]
                          if ns == DEST_NS else []),
                "readinessProbe": ({"httpGet": {"path": "/ready", "port": PORT},
                                    "periodSeconds": 2, "failureThreshold": 20}
                                   if ns == DEST_NS else
                                   {"exec": {"command": ["python", "-c", "pass"]},
                                    "periodSeconds": 2, "failureThreshold": 20}),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True},
            }],
        },
    }


BACKEND_SERVER = r'''from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body={"path":self.path,"xfcc":self.headers.get("x-forwarded-client-cert",""),
        "traceparent":self.headers.get("traceparent","")}
  data=json.dumps(body).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
 def log_message(self,*a): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''
CLIENT_SLEEP = "import time; time.sleep(3600)"


def backend_service():
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": BACKEND, "namespace": DEST_NS,
                         "labels": {"saf-k8s.example/0504-002-fixture": "true"}},
            "spec": {"selector": {"app": BACKEND},
                     "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]}}


def probe(lab, client, *, trace_id=None, endpoint=PATH):
    traceparent = f"00-{trace_id}-0123456789abcdef-01" if trace_id else ""
    script = r'''import http.client,json,sys,urllib.request,urllib.error
url=sys.argv[1]; trace=sys.argv[2]
headers={"traceparent":trace,"x-saf-trace-marker":"saf-0504-002-owned-trace"} if trace else {}
req=urllib.request.Request(url,headers=headers)
try:
 r=urllib.request.urlopen(req,timeout=8); print(json.dumps({"status":r.status,"body":json.loads(r.read())}))
except urllib.error.HTTPError as e: print(json.dumps({"status":e.code,"body":e.read().decode(errors="replace")}))
except (ConnectionResetError,http.client.RemoteDisconnected) as e: print(json.dumps({"transport_rejected":True}))
except urllib.error.URLError as e: print(json.dumps({"transport_rejected":isinstance(e.reason,ConnectionResetError),"error":type(e.reason).__name__}))
'''
    result = kubectl(lab, "-n", SOURCE_NS, "exec", f"pod/{client}", "-c", "app", "--",
                     "python", "-c", script,
                     f"http://{BACKEND}.{DEST_NS}.svc.cluster.local:{PORT}{endpoint}",
                     traceparent, timeout=20)
    return json.loads(result.stdout.strip())


def auth_policy():
    return {
        "apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
        "metadata": {"name": "approved-client-only", "namespace": DEST_NS,
                     "labels": {"saf-k8s.example/0504-002-fixture": "true"}},
        "spec": {"selector": {"matchLabels": {"app": BACKEND}}, "action": "ALLOW",
                 "rules": [{"from": [{"source": {"principals": [
                     f"cluster.local/ns/{SOURCE_NS}/sa/{ALLOWED_CLIENT}"]}}],
                     "to": [{"operation": {"methods": ["GET"], "paths": [PATH]}}]}]},
    }


def assert_check(lab, phase, label, predicate, observed):
    lab.check(phase, label, bool(predicate), observed)


def wait_for_trace(lab, client, trace_id):
    script = r'''import json,sys,urllib.error,urllib.parse,urllib.request
base="http://tracing.istio-system.svc.cluster.local/jaeger/api/"
marker="saf-0504-002-owned-trace"
def get(path):
    with urllib.request.urlopen(base+path,timeout=5) as response:
        return json.load(response).get("data",[])
try:
    services=get("services")
    try:
        traces=get("traces/"+sys.argv[1])
    except urllib.error.HTTPError as e:
        if e.code!=404: raise
        traces=[]
    for service in services:
        if "approved-client" in service or "-backend" in service:
            tags=json.dumps({"saf.fixture.request":marker})
            params=urllib.parse.urlencode({"service":service,"tags":tags,"limit":10})
            traces.extend(get("traces?"+params))
    for trace in traces:
        processes=trace.get("processes",{})
        selected=[span for span in trace.get("spans",[]) if any(
            tag.get("key")=="saf.fixture.request" and tag.get("value")==marker for tag in span.get("tags",[]))]
        names={processes.get(span.get("processID"),{}).get("serviceName","") for span in selected}
        if any("approved-client" in n for n in names) and any("-backend" in n for n in names):
            print(json.dumps({"trace_found":True,"client_span":True,"backend_span":True,"exact_fixture_marker":True}))
            break
    else:
        print(json.dumps({"trace_found":False,"services":services,"trace_count":len(traces)}))
except urllib.error.URLError as error:
    print(json.dumps({"trace_found":False,"error":str(error)}))
'''
    deadline = time.monotonic() + 45
    observed = {"trace_found": False}
    while time.monotonic() < deadline:
        output = kubectl(lab, "-n", SOURCE_NS, "exec", f"pod/{client}", "-c", "app", "--",
                         "python", "-c", script, trace_id, timeout=22)
        observed = json.loads(output.stdout.strip())
        if observed["trace_found"]:
            return True, observed
        time.sleep(0.7)
    kubectl(lab, "-n", "istio-system", "logs", "deployment/jaeger", "--tail=30", allow_failure=True)
    return False, observed


def metrics(lab, backend_pod):
    result = kubectl(lab, "-n", DEST_NS, "exec", f"pod/{backend_pod}", "-c", "istio-proxy",
                     "--", "pilot-agent", "request", "GET", "stats/prometheus", timeout=20)
    text = result.stdout
    rows = [line for line in text.splitlines()
            if line.startswith("istio_requests_total{") and f'destination_service="{BACKEND}.{DEST_NS}.svc.cluster.local"' in line]
    codes = {code: any(f'response_code="{code}"' in row for row in rows) for code in ("200", "403")}
    protected = any('connection_security_policy="mutual_tls"' in row and 'response_code="200"' in row for row in rows)
    return {"request_metrics_present": bool(rows), "response_codes_observed": codes,
            "successful_mutual_tls_metric": protected}


def run(lab):
    server_version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "Pinned Kubernetes v1.36.1 Kind control plane",
              server_version == "v1.36.1", {"server_version": server_version,
                                           "node_image": NODE_IMAGE})
    workdir = lab.kubeconfig.parent
    istioctl, release_dir = download_istio(lab, workdir)
    install_mesh(lab, istioctl, release_dir, workdir)

    # Start with the exact same two source identities and destination request
    # outside the mesh. This red phase establishes reachable plaintext behavior.
    json_resource(lab, namespace(SOURCE_NS))
    json_resource(lab, namespace(DEST_NS))
    for ns in (SOURCE_NS, DEST_NS):
        json_resource(lab, {"apiVersion": "telemetry.istio.io/v1", "kind": "Telemetry",
                            "metadata": {"name": "fixture-tracing", "namespace": ns},
                            "spec": {"tracing": [{"providers": [{"name": "jaeger"}],
                                                   "randomSamplingPercentage": 100.0,
                                                   "customTags": {"saf.fixture.request": {"header": {
                                                       "name": "x-saf-trace-marker", "defaultValue": ""}}}}]}})
    for sa in (ALLOWED_CLIENT, DENIED_CLIENT, PLAIN_CLIENT):
        json_resource(lab, service_account(sa, SOURCE_NS))
    json_resource(lab, service_account(f"{NAMESPACE}-backend", DEST_NS))
    json_resource(lab, pod(BACKEND, DEST_NS, f"{NAMESPACE}-backend", {"app": BACKEND}, BACKEND_SERVER))
    json_resource(lab, backend_service())
    for client, sa in ((ALLOWED_CLIENT, ALLOWED_CLIENT), (DENIED_CLIENT, DENIED_CLIENT)):
        json_resource(lab, pod(client, SOURCE_NS, sa, {"app": client}, CLIENT_SLEEP))
    plain = pod(PLAIN_CLIENT, SOURCE_NS, PLAIN_CLIENT, {"app": PLAIN_CLIENT}, CLIENT_SLEEP)
    plain["metadata"]["labels"]["sidecar.istio.io/inject"] = "false"
    json_resource(lab, plain)
    wait_ready(lab, SOURCE_NS, PLAIN_CLIENT)
    wait_ready(lab, DEST_NS, BACKEND)
    for client in (ALLOWED_CLIENT, DENIED_CLIENT, PLAIN_CLIENT):
        wait_ready(lab, SOURCE_NS, client)
    for client in (ALLOWED_CLIENT, DENIED_CLIENT, PLAIN_CLIENT):
        response = probe(lab, client)
        body = response.get("body", {})
        assert_check(lab, "red", f"Unmeshed {client} reaches the same owned backend request",
                     response.get("status") == 200 and body.get("path") == PATH and not body.get("xfcc"),
                     {"status": response.get("status"), "xfcc_present": bool(body.get("xfcc"))})

    # Opt both namespaces into sidecar injection and recreate only case-owned Pods.
    json_resource(lab, namespace(SOURCE_NS, inject=True))
    json_resource(lab, namespace(DEST_NS, inject=True))
    kubectl(lab, "-n", SOURCE_NS, "delete", "pod", ALLOWED_CLIENT, DENIED_CLIENT)
    kubectl(lab, "-n", DEST_NS, "delete", "pod", BACKEND)
    time.sleep(2)
    for client, sa in ((ALLOWED_CLIENT, ALLOWED_CLIENT), (DENIED_CLIENT, DENIED_CLIENT)):
        json_resource(lab, pod(client, SOURCE_NS, sa, {"app": client}, CLIENT_SLEEP))
    json_resource(lab, pod(BACKEND, DEST_NS, f"{NAMESPACE}-backend", {"app": BACKEND}, BACKEND_SERVER))
    for ns, name in ((SOURCE_NS, ALLOWED_CLIENT), (SOURCE_NS, DENIED_CLIENT), (DEST_NS, BACKEND)):
        wait_ready(lab, ns, name)
    for client in (ALLOWED_CLIENT, DENIED_CLIENT):
        response = probe(lab, client)
        body = response.get("body", {})
        expected = f"URI=spiffe://cluster.local/ns/{SOURCE_NS}/sa/{client}"
        assert_check(lab, "green", f"Injected request carries authenticated {client} identity",
                     response.get("status") == 200 and expected in body.get("xfcc", ""),
                     {"status": response.get("status"), "peer_principal_matches": expected in body.get("xfcc", "")})

    # STRICT prevents plaintext downgrade at this fixture backend; the ALLOW
    # policy then scopes the ordinary GET to one source principal.
    json_resource(lab, {"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication",
                        "metadata": {"name": "strict-fixture-mtls", "namespace": DEST_NS,
                                     "labels": {"saf-k8s.example/0504-002-fixture": "true"}},
                        "spec": {"selector": {"matchLabels": {"app": BACKEND}},
                                 "mtls": {"mode": "STRICT"}}})
    deadline = time.monotonic() + 25
    while True:
        rejected = probe(lab, PLAIN_CLIENT)
        if rejected.get("transport_rejected") or time.monotonic() >= deadline:
            break
        time.sleep(0.4)
    lab.check("green", "The reachable unmeshed client is rejected at the STRICT transport boundary",
              rejected.get("transport_rejected") is True, {"plaintext_transport_rejected": rejected.get("transport_rejected") is True})
    json_resource(lab, auth_policy())
    kubectl(lab, "-n", DEST_NS, "get", "authorizationpolicy", "approved-client-only", "-o", "name")

    trace_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    allowed = probe(lab, ALLOWED_CLIENT, trace_id=trace_id)
    allowed_body = allowed.get("body", {})
    assert_check(lab, "green", "Authorized service-account identity receives the same GET",
                 allowed.get("status") == 200 and
                 f"URI=spiffe://cluster.local/ns/{SOURCE_NS}/sa/{ALLOWED_CLIENT}" in allowed_body.get("xfcc", "") and
                 trace_id in allowed_body.get("traceparent", ""),
                 {"status": allowed.get("status"), "trace_context_matches": trace_id in allowed_body.get("traceparent", "")})
    deadline = time.monotonic() + 25
    while True:
        denied = probe(lab, DENIED_CLIENT)
        if denied.get("status") == 403 or time.monotonic() >= deadline:
            break
        time.sleep(0.4)
    assert_check(lab, "positive", "Same request from the other service account is denied by policy",
                 denied.get("status") == 403 and "RBAC" in denied.get("body", ""),
                 {"status": denied.get("status"), "policy": "approved-client-only"})

    metric_observation = metrics(lab, BACKEND)
    assert_check(lab, "positive", "Backend proxy exposes request metrics for allowed and denied requests",
                 metric_observation["request_metrics_present"] and metric_observation["successful_mutual_tls_metric"] and
                 all(metric_observation["response_codes_observed"].values()), metric_observation)
    trace_found, trace_observation = wait_for_trace(lab, ALLOWED_CLIENT, trace_id)
    assert_check(lab, "positive", "Jaeger stores client and backend spans for the same traced request",
                 trace_found, trace_observation)
