"""Observe synthetic prefix-cache key scoping and a two-request queue fixture."""
import http.client
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0902-006"
NAMESPACE = "saf-test"
APP = "saf-0902-006"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
PORT = 8080
SERVICE = f"{APP}-serving"
SCOPE = (
    "One disposable Kind v1.36.1 cluster runs one case-owned Python mock serving process "
    "from a digest-pinned Docker Official Python image. The fixture maps one fixed public "
    "content string to a synthetic prefix digest, maintains bounded in-memory cache and "
    "accounting state and returns a fixed mock marker without per-request cache telemetry. Red demonstrates the unscoped "
    "comparator; green demonstrates a tenant-scoped synthetic key; positive demonstrates "
    "exact same-tenant/same-prefix reuse. Two ordinary requests occupy one active and one queued slot, "
    "and an additional fixed request is refused by the fixture's depth cap. Raw observations omit content, salts, and credentials. "
    "No LLM, model, GPU, inference framework, real prompt, secret, feed, target, or attack "
    "is present. This does not establish vLLM/TGI/Triton behavior, KV-memory zeroing, "
    "tenant isolation, production queue limits, or framework-level scheduling."
)
LABELS = {"saf-lab.example/control": CONTROL_ID,
          "saf-lab.example/fixture": "synthetic"}


def _config_map():
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"{APP}-code", "namespace": NAMESPACE,
                     "labels": LABELS},
        "immutable": True,
        "data": {"serving.py": (HERE / "fixtures" / "serving.py").read_text(encoding="utf-8")},
    }


def _workload(scoped):
    pod_labels = {**LABELS, "app": APP}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": APP, "namespace": NAMESPACE, "labels": LABELS},
        "spec": {
            "replicas": 1, "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app": APP}},
            "template": {"metadata": {"labels": pod_labels}, "spec": {
                "automountServiceAccountToken": False,
                "terminationGracePeriodSeconds": 1,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "mock-serving", "image": IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-B", "/fixture/serving.py"],
                    "env": [{"name": "CACHE_TENANT_SCOPE", "value": str(scoped).lower()}],
                    "ports": [{"name": "http", "containerPort": PORT}],
                    "readinessProbe": {"httpGet": {"path": "/health", "port": PORT},
                                       "periodSeconds": 2, "failureThreshold": 30},
                    "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                         "readOnlyRootFilesystem": True,
                                         "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                      "readOnly": True}],
                }],
                "volumes": [{"name": "fixture", "configMap": {"name": f"{APP}-code"}}],
            }},
        },
    }


def _service():
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": SERVICE, "namespace": NAMESPACE, "labels": LABELS},
            "spec": {"type": "ClusterIP", "selector": {"app": APP},
                     "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]}}


def _forward(lab):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        local_port = reservation.getsockname()[1]
    process = subprocess.Popen(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "port-forward", f"service/{SERVICE}",
         f"{local_port}:{PORT}", "--address", "127.0.0.1"], env=lab.env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Port-forward exited for the case-owned mock service")
        try:
            status, _ = _request(local_port, "GET", "/health")
            if status == 200:
                return process, local_port
        except OSError:
            pass
        time.sleep(0.2)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError("Timed out waiting for case-owned mock service")


def _stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _request(port, method, path, value=None, timeout=5):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() if value is not None else None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body,
                           headers={"Content-Type": "application/json"} if body else {})
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def _observation(lab, name, value):
    path = lab.evidence / name
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _check_response(lab, claim, status, result, *, tenant, event_id):
    expected = {"event_id": event_id, "tenant": tenant, "prefix_id": "public-fixture-prefix-1",
                "result": "SAF-SYNTHETIC-MOCK-RESULT-0902-006"}
    lab.check("positive", claim, status == 200 and result == expected,
              {"status": status, "exact_fixture_response": result == expected,
               "tenant": tenant, "event_id": event_id})


def run(lab):
    # This case creates only its own namespaced mock resources.
    lab.create(_config_map())
    lab.create(_service())
    lab.create(_workload(False))
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{APP}",
                "--timeout=120s", timeout=130)

    process, port = _forward(lab)
    try:
        # Deliberately open comparator: no tenant component is included in the mock key.
        lab.check("positive", "Case-owned fixture reports unscoped red-comparator mode",
                  _request(port, "GET", "/state")[1]["tenant_scope"] is False,
                  {"tenant_scope": False, "cache_entries": 0})
        red_a = _request(port, "POST", "/infer", {"event_id": "red-a", "tenant": "tenant-a",
                                                   "fixture_id": "public-fixture-prefix-1"})
        red_b = _request(port, "POST", "/infer", {"event_id": "red-b", "tenant": "tenant-b",
                                                   "fixture_id": "public-fixture-prefix-1"})
        _check_response(lab, "The comparator responds normally to the two known fixture tenants",
                        *red_a, tenant="tenant-a", event_id="red-a")
        _check_response(lab, "The second comparator response omits per-request cache state",
                        *red_b, tenant="tenant-b", event_id="red-b")
        red_state = _request(port, "GET", "/state")[1]
        red_receipt = {"tenant_scope": red_state["tenant_scope"], "cache_entries": red_state["cache_entries"],
                       "hits": red_state["cache_hits"], "misses": red_state["cache_misses"],
                       "cross_tenant_reuse_count": red_state["cross_tenant_reuse_count"]}
        _observation(lab, "red-cache-accounting.raw.json", red_receipt)
        lab.check("red", "Independent fixture accounting observes one unscoped cross-tenant reuse",
                  red_receipt == {"tenant_scope": False, "cache_entries": 1, "hits": 1,
                                  "misses": 1, "cross_tenant_reuse_count": 1}, red_receipt)
    finally:
        _stop(process)

    lab.kubectl("-n", NAMESPACE, "set", "env", f"deployment/{APP}", "CACHE_TENANT_SCOPE=true")
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{APP}",
                "--timeout=120s", timeout=130)
    process, port = _forward(lab)
    try:
        state = _request(port, "GET", "/state")[1]
        lab.check("positive", "Fresh enforced fixture starts with tenant-scoped cache accounting",
                  state == {"tenant_scope": True, "cache_entries": 0, "cache_hits": 0,
                            "cache_misses": 0, "cross_tenant_reuse_count": 0,
                            "queue_active": 0, "queue_depth": 0, "queue_peak_depth": 0,
                            "queue_max_active": 1, "queue_max_depth": 1}, state)

        a1 = _request(port, "POST", "/infer", {"event_id": "green-a1", "tenant": "tenant-a",
                                                "fixture_id": "public-fixture-prefix-1"})
        after_a = _request(port, "GET", "/state")[1]
        b1 = _request(port, "POST", "/infer", {"event_id": "green-b1", "tenant": "tenant-b",
                                                "fixture_id": "public-fixture-prefix-1"})
        after_b = _request(port, "GET", "/state")[1]
        b2 = _request(port, "POST", "/infer", {"event_id": "positive-b2", "tenant": "tenant-b",
                                                "fixture_id": "public-fixture-prefix-1"})
        for response, tenant, event in ((a1, "tenant-a", "green-a1"),
                                        (b1, "tenant-b", "green-b1"),
                                        (b2, "tenant-b", "positive-b2")):
            _check_response(lab, "A scoped fixture reply returns the fixed result without exposing cache state",
                            *response, tenant=tenant, event_id=event)
        cache_state = _request(port, "GET", "/state")[1]
        cache_receipt = {"tenant_scope": cache_state["tenant_scope"],
                         "cache_entries": cache_state["cache_entries"],
                         "hits": cache_state["cache_hits"], "misses": cache_state["cache_misses"],
                         "cross_tenant_reuse_count": cache_state["cross_tenant_reuse_count"]}
        _observation(lab, "green-cache-accounting.raw.json", {"after_tenant_a": after_a,
                                                              "after_tenant_b": after_b, "final": cache_receipt})
        lab.check("green", "Independent accounting records distinct misses for the same prefix in two tenants",
                  after_a["cache_entries"] == 1 and after_a["cache_misses"] == 1 and after_a["cache_hits"] == 0
                  and after_b["cache_entries"] == 2 and after_b["cache_misses"] == 2 and after_b["cache_hits"] == 0,
                  {"first_scoped_entry_count": after_a["cache_entries"],
                   "second_scoped_entry_count": after_b["cache_entries"], "both_scoped_requests_missed": after_b["cache_misses"] == 2})
        lab.check("green", "Independent scoped cache accounting shows isolated misses and same-tenant reuse",
                  cache_receipt == {"tenant_scope": True, "cache_entries": 2, "hits": 1,
                                    "misses": 2, "cross_tenant_reuse_count": 0}, cache_receipt)

        # Two ordinary tiny fixture requests exercise occupancy and queue-depth accounting.
        first_result = {}
        def first_request():
            first_result["value"] = _request(port, "POST", "/queue",
                                               {"event_id": "queue-a", "tenant": "tenant-a",
                                                "fixture_id": "tiny-1"}, timeout=10)

        first = threading.Thread(target=first_request, daemon=True)
        first.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = _request(port, "GET", "/state")[1]
            if state["queue_active"] == 1:
                break
            time.sleep(0.05)
        else:
            lab.block("First normal fixture request did not become active")
        second_result = {}
        def second_request():
            second_result["value"] = _request(port, "POST", "/queue",
                                                {"event_id": "queue-b", "tenant": "tenant-b",
                                                 "fixture_id": "tiny-2"}, timeout=10)

        second = threading.Thread(target=second_request, daemon=True)
        second.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            queue_state = _request(port, "GET", "/state")[1]
            if queue_state["queue_depth"] == 1:
                break
            time.sleep(0.05)
        else:
            lab.block("Second normal fixture request did not produce an observable queued request")
        queue_receipt = {"active": queue_state["queue_active"], "depth": queue_state["queue_depth"],
                         "peak_depth": queue_state["queue_peak_depth"],
                         "max_active": queue_state["queue_max_active"],
                         "max_depth": queue_state["queue_max_depth"]}
        _observation(lab, "queue-accounting.raw.json", queue_receipt)
        lab.check("green", "Two-request fixture observes one active and one queued request within declared bounds",
                  queue_receipt == {"active": 1, "depth": 1, "peak_depth": 1,
                                    "max_active": 1, "max_depth": 1}, queue_receipt)
        declined = _request(port, "POST", "/queue", {"event_id": "queue-c", "tenant": "tenant-a",
                                                       "fixture_id": "tiny-1"})
        after_decline = _request(port, "GET", "/state")[1]
        lab.check("green", "One additional normal fixture request is rejected when queue capacity is occupied",
                  declined == (429, {"error": "fixture-queue-full"}) and after_decline == queue_state,
                  {"status": declined[0], "occupancy_unchanged": after_decline == queue_state})
        status, release = _request(port, "POST", "/fixture/release", {})
        lab.check("positive", "Fixture-only release lets both normal requests complete",
                  status == 200 and release == {"released": True},
                  {"status": status, "released": release})
        first.join(timeout=10)
        second.join(timeout=10)
        both_complete = (not first.is_alive() and not second.is_alive()
                         and first_result.get("value") == (200, {"event_id": "queue-a", "result": "SAF-SYNTHETIC-MOCK-RESULT-0902-006"})
                         and second_result.get("value") == (200, {"event_id": "queue-b", "result": "SAF-SYNTHETIC-MOCK-RESULT-0902-006"}))
        drained = _request(port, "GET", "/state")[1]
        _observation(lab, "queue-accounting.raw.json", {"occupied": queue_receipt, "after_rejection": after_decline,
                                                         "after_release": drained, "responses": [first_result, second_result]})
        both_complete = both_complete and drained["queue_active"] == drained["queue_depth"] == 0
        lab.check("positive", "Both bounded normal queue requests complete with mock results",
                  both_complete, {"completed": both_complete,
                                  "request_count": len(first_result) + len(second_result)})
    finally:
        _stop(process)
