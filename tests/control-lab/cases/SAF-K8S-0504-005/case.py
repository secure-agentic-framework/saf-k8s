"""Bounded Istio sidecar resource tuning and local availability witness."""
import json
import importlib.util
from pathlib import Path
import time


CONTROL_ID = "SAF-K8S-0504-005"
ISTIO_VERSION = "1.32.0"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BACKEND = "saf-0504-005-backend"
CLIENT = "saf-0504-005-client"
CASE_LABEL = "saf-k8s.example/0504-005-fixture"
PORT = 8080
PATH = "/owned/inference-fixture"
TUNED = {
    "sidecar.istio.io/proxyCPU": "100m",
    "sidecar.istio.io/proxyCPULimit": "200m",
    "sidecar.istio.io/proxyMemory": "64Mi",
    "sidecar.istio.io/proxyMemoryLimit": "128Mi",
}
SCOPE = (
    "One fresh disposable Kind v1.36.1 cluster, the published adjacent case's "
    "Istio 1.32.0 sidecar runtime, two case-owned Python fixture Pods, and one "
    "additional inert Pod with a per-Pod injection opt-out label in the "
    "injection-enabled runner namespace. The opt-out Pod sends no requests. Compares "
    "a small finite set of local GETs "
    "before and after applying documented Envoy proxy CPU/memory annotations to "
    "the backend. Reads the injected istio-proxy request/limit values from the Pod "
    "spec and checks bounded authenticated request availability. A server-side dry-run of a "
    "candidate whose proxy CPU request exceeds its limit exercises the admission "
    "rollback guard without mutating the known-good Pod. Throughput, GPU behavior, "
    "mTLS overhead, and production availability remain unverified."
)


def kubectl(lab, *args, timeout=45, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", f"--request-timeout={max(5, timeout - 5)}s", *args, timeout=timeout, **kwargs,
    )


def save_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def resource(lab, obj):
    return kubectl(lab, "apply", "-f", "-", payload=json.dumps(obj))


def pod(name, command, annotations=None, ports=False):
    metadata = {"name": name, "labels": {"app": name, CASE_LABEL: "true"}}
    if annotations:
        metadata["annotations"] = annotations
    container = {
        "name": "fixture", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-u", "-c", command],
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                     "limits": {"cpu": "200m", "memory": "128Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "readOnlyRootFilesystem": True},
    }
    if ports:
        container["ports"] = [{"name": "http", "containerPort": PORT}]
        container["readinessProbe"] = {"httpGet": {"path": "/ready", "port": PORT},
                                        "periodSeconds": 2, "failureThreshold": 20}
    else:
        container["readinessProbe"] = {"exec": {"command": ["python", "-c", "pass"]},
                                        "periodSeconds": 2, "failureThreshold": 20}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
            "spec": {"serviceAccountName": "default", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                         "runAsGroup": 65532,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container]}}


SERVER = r'''from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path == "/ready":
   self.send_response(200); self.end_headers(); return
  body=json.dumps({"path":self.path,"fixture":"saf-0504-005-owned"}).encode()
  self.send_response(200); self.send_header("Content-Type","application/json")
  self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*a): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''
CLIENT_SLEEP = "import time; time.sleep(3600)"


def wait_ready(lab, name, timeout=180):
    kubectl(lab, "wait", "--for=condition=Ready", f"pod/{name}",
            f"--timeout={timeout}s", timeout=timeout + 10)


def probe(lab, marker):
    script = r'''import json,sys,urllib.request
url=sys.argv[1]; rows=[]
request = urllib.request.Request(url, headers={"X-SAF-Case": sys.argv[2]})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for n in range(3):
 try:
  with opener.open(request,timeout=6) as r:
   body=json.loads(r.read()); rows.append({"status":r.status,"path":body.get("path"),"fixture":body.get("fixture")})
 except Exception as e: rows.append({"error":type(e).__name__})
print(json.dumps(rows,sort_keys=True))
'''
    result = kubectl(lab, "exec", f"pod/{CLIENT}", "-c", "fixture", "--", "python", "-c",
                     script, f"http://{BACKEND}:8080{PATH}", marker, timeout=30)
    return json.loads(result.stdout.strip())


def snapshot(lab, name):
    return json.loads(kubectl(lab, "get", "pod", name, "-o", "json").stdout)


def sidecar_resources(pod_json):
    containers = pod_json.get("spec", {}).get("containers", [])
    sidecars = [entry for entry in pod_json["spec"].get("initContainers", [])
                if entry.get("restartPolicy") == "Always"]
    proxy = [c for c in [*containers, *sidecars] if c.get("name") == "istio-proxy"]
    if len(proxy) != 1:
        return {"proxy_count": len(proxy)}
    resources = proxy[0].get("resources", {})
    return {"requests": resources.get("requests", {}), "limits": resources.get("limits", {})}


def all_ok(rows):
    return len(rows) == 3 and all(
        row == {"status": 200, "path": PATH, "fixture": "saf-0504-005-owned"}
        for row in rows
    )


def await_route(lab):
    deadline = time.monotonic() + 30
    while not all_ok(probe(lab, "availability-readiness")):
        if time.monotonic() >= deadline:
            lab.block("Case-owned mesh route did not become ready")
        time.sleep(0.5)


def observed_requests(lab, name):
    rows = probe(lab, name)
    peer = f"SAF-PEER|spiffe://cluster.local/ns/saf-test/sa/default|{name}|{PATH}|200"
    deadline = time.monotonic() + 12
    while True:
        logged = kubectl(lab, "logs", BACKEND, "-c", "istio-proxy").stdout.splitlines()
        if logged.count(peer) >= 3:
            return rows, True
        if time.monotonic() >= deadline:
            return rows, False
        time.sleep(0.5)


def assert_check(lab, phase, claim, condition, observed):
    lab.check(phase, claim, bool(condition), observed)


def run(lab):
    server_version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "Pinned Kubernetes v1.36.1 Kind control plane",
              server_version == "v1.36.1", {"server_version": server_version})

    # Use the previously verified pinned Istio sidecar case.
    from importlib.util import spec_from_file_location, module_from_spec
    adjacent = (Path(__file__).resolve().parent.parent /
                "SAF-K8S-0504-001" / "case.py")
    spec = spec_from_file_location("saf_k8s_0504_002_fixture", adjacent)
    if spec is None or spec.loader is None:
        lab.block("Published adjacent Istio fixture helper is unavailable in this source checkout")
    fixture = module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.install(lab)
    pinned_proxy = {"sidecar.istio.io/proxyImage": fixture.PROXY_IMAGE}
    fixture.apply_config(lab, "PeerAuthentication", "mesh-fixture-mtls", {"mtls": {"mode": "STRICT"}})

    # Compare two samples through the same strict mTLS Service. Only backend
    # proxy resource annotations change before the second sample.
    resource(lab, {"apiVersion": "v1", "kind": "Service",
                   "metadata": {"name": BACKEND, "labels": {CASE_LABEL: "true"}},
                   "spec": {"selector": {"app": BACKEND},
                            "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]}})
    resource(lab, pod(BACKEND, SERVER, annotations=pinned_proxy, ports=True))
    resource(lab, pod(CLIENT, CLIENT_SLEEP, annotations=pinned_proxy))
    wait_ready(lab, BACKEND)
    wait_ready(lab, CLIENT)
    await_route(lab)
    red_rows, red_authenticated = observed_requests(lab, "resources-baseline")
    baseline = snapshot(lab, BACKEND)
    defaults = sidecar_resources(baseline)
    save_json(lab.evidence / "availability-red.raw.json", {"rows": red_rows, "pod": baseline})
    assert_check(lab, "red", "The default proxy serves three exact authenticated fixture requests",
                 all_ok(red_rows) and red_authenticated and "requests" in defaults,
                 {"requests": len(red_rows), "authenticated": red_authenticated,
                  "default_proxy_resources": defaults})

    kubectl(lab, "delete", "pod", BACKEND, "--wait=true", "--timeout=40s", timeout=50)
    resource(lab, pod(BACKEND, SERVER, annotations={**pinned_proxy, **TUNED}, ports=True))
    wait_ready(lab, BACKEND)
    await_route(lab)
    live = snapshot(lab, BACKEND)
    observed = sidecar_resources(live)
    expected = {"requests": {"cpu": "100m", "memory": "64Mi"},
                "limits": {"cpu": "200m", "memory": "128Mi"}}
    green_rows, green_authenticated = observed_requests(lab, "resources-tuned")
    save_json(lab.evidence / "tuned-green.raw.json",
              {"pod": live, "availability_requests": green_rows})
    assert_check(lab, "green", "Documented Istio proxy resource annotations become exact injected requests and limits",
                 observed == expected and defaults != expected, observed)
    assert_check(lab, "green", "Tuned backend retains three of three exact local GET responses",
                 all_ok(green_rows) and green_authenticated,
                 {"requests": len(green_rows), "all_exact_200": all_ok(green_rows),
                  "authenticated": green_authenticated})

    # Candidate fails admission before it can replace the ready known-good Pod.
    # This is the bounded rollback guard: request > limit, or any failed local
    # GET / resource mismatch, means restore the recorded known-good template.
    bad = {**pinned_proxy, **TUNED}
    bad["sidecar.istio.io/proxyCPU"] = "300m"
    candidate = pod("saf-0504-005-candidate", CLIENT_SLEEP, annotations=bad)
    rejected = kubectl(lab, "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(candidate), allow_failure=True)
    after = snapshot(lab, BACKEND)
    post_rows, post_authenticated = observed_requests(lab, "resources-known-good")
    admission_text = (rejected.stderr + rejected.stdout).lower()
    rejection = {"exit_code": rejected.returncode,
                 "stderr": rejected.stderr.strip(), "stdout": rejected.stdout.strip()}
    rollback = {"candidate_rejected_for_cpu_request_over_limit":
                    rejected.returncode != 0 and "must be less than or equal to cpu limit" in admission_text,
                "known_good_uid_unchanged": after["metadata"]["uid"] == live["metadata"]["uid"],
                "proxy_resources_unchanged": sidecar_resources(after) == expected,
                "availability_3_of_3": all_ok(post_rows) and post_authenticated}
    save_json(lab.evidence / "rollback-positive.raw.json",
              {"candidate_admission": rejection, "known_good_before": live,
               "known_good_after": after, "availability_requests": post_rows,
               "rollback_guard": rollback})
    assert_check(lab, "positive", "Over-budget candidate is rejected and the exact known-good proxy and 3/3 connectivity remain in service",
                 all(rollback.values()), rollback)

    selective_path = Path(__file__).with_name("selective_injection.py")
    selective_spec = importlib.util.spec_from_file_location("saf_0504_005_selective_injection", selective_path)
    if selective_spec is None or selective_spec.loader is None:
        lab.block("Could not load the case-local selective-injection comparison")
    selective_module = importlib.util.module_from_spec(selective_spec)
    selective_spec.loader.exec_module(selective_module)
    selective = selective_module.run(
        lab, pod_factory=pod, resource=resource, wait_ready=wait_ready, snapshot=snapshot,
        sidecar_resources=sidecar_resources, observed_requests=observed_requests,
        assert_check=assert_check, pinned_proxy=pinned_proxy, client_sleep=CLIENT_SLEEP,
        expected_resources=expected, kubectl=kubectl,
    )

    normalized = {
        "control_id": CONTROL_ID,
        "runtime": {"istio_version": ISTIO_VERSION, "kubernetes_version": server_version,
                    "python_image": PYTHON_IMAGE},
        "phases": {
            "red": {"request_count": len(red_rows), "exact_success_count": sum(
                row == {"status": 200, "path": PATH, "fixture": "saf-0504-005-owned"} for row in red_rows)},
            "green": {"sidecar_resources": observed, "request_count": len(green_rows),
                      "exact_success_count": sum(
                          row == {"status": 200, "path": PATH, "fixture": "saf-0504-005-owned"} for row in green_rows)},
            "positive": rollback,
            "selective_injection": selective,
        },
        "measured_guard": {"candidate_cpu_request_exceeds_limit": True,
                           "availability_threshold": "3 of 3 exact fixture GETs return HTTP 200",
                           "resource_threshold": expected},
        "claim_boundary": "No throughput, latency benchmark, GPU/NCCL, or production availability result.",
    }
    save_json(lab.evidence / "normalized.json", normalized)
