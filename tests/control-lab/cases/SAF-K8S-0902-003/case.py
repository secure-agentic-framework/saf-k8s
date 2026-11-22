"""Exercise bounded schema checks on owned mock gateway and model services."""
import http.client
import json
from pathlib import Path
import socket
import subprocess
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-0902-003"
NAMESPACE = "saf-test"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
LABEL = "saf-lab.example/control"
APP = "saf-0902-003"
SCOPE = (
    "One disposable Kind v1.36.1 cluster runs case-owned gateway, model, and backend mock "
    "processes from a digest-pinned official Python image. The gateway and mock model each "
    "enforce the exact two-field JSON object schema and a 128-byte request-body limit. "
    "Benign typed fixtures test one schema-invalid object and one otherwise-valid object "
    "exactly one byte over the limit; valid requests must return the exact mock marker. "
    "With checks disabled, both benign comparators reach the recorder. "
    "An independently queried backend counter and request ID establish which requests "
    "reached the local backend. No external targets, feeds, model, gateway product, "
    "injection content, adversarial input, exploit, or production workload is used. "
    "This does not establish adversarial detection, sanitization, injection prevention, "
    "model robustness, batch/gRPC/streaming coverage, or organization-wide deployment."
)


def _labels():
    return {LABEL: CONTROL_ID, "saf-lab.example/fixture": "true"}


def _config_map(policy):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"{APP}-fixtures", "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"policy.json": json.dumps(policy, sort_keys=True),
                 "server.py": (FIXTURES / "server.py").read_text(encoding="utf-8")},
    }


def _container(name, mode, port):
    return {
        "name": name, "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-B", "/fixture/server.py"],
        "env": [{"name": "MODE", "value": mode}, {"name": "FIXTURE_ENFORCE", "value": "false"}],
        "ports": [{"name": name, "containerPort": port}],
        "readinessProbe": {"httpGet": {"path": "/health", "port": port},
                           "periodSeconds": 2, "failureThreshold": 30},
        "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True,
                             "runAsNonRoot": True, "runAsUser": 65534,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
    }


def _resources():
    pod_labels = {"app": APP, **_labels()}
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": APP, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                 "selector": {"matchLabels": {"app": APP}},
                 "template": {"metadata": {"labels": pod_labels},
                              "spec": {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 1,
                                       "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [_container("gateway", "gateway", 8080),
                                                      _container("model", "model", 9001),
                                                      _container("backend", "backend", 9002)],
                                       "volumes": [{"name": "fixture", "configMap":
                                                    {"name": f"{APP}-fixtures"}}]}}},
    }
    services = []
    for name, port, target in (("gateway", 8080, "gateway"),
                               ("model", 9001, "model"),
                               ("backend", 9002, "backend")):
        services.append({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": f"{APP}-{name}", "namespace": NAMESPACE, "labels": _labels()},
            "spec": {"type": "ClusterIP", "selector": {"app": APP},
                     "ports": [{"name": name, "port": port, "targetPort": target}]},
        })
    return [deployment, *services]


def _forward(lab, service, target_port):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        local_port = reservation.getsockname()[1]
    process = subprocess.Popen(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "port-forward", f"service/{service}",
         f"{local_port}:{target_port}"],
        env=lab.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Port-forward exited for case-owned service {service}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", local_port, timeout=1)
            connection.request("GET", "/health" if target_port != 9002 else "/state")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return process, local_port
        except OSError:
            pass
        finally:
            if "connection" in locals():
                connection.close()
        time.sleep(0.2)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError(f"Timed out starting port-forward for case-owned service {service}")


def _request(port, method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _backend_state(port):
    status, body = _request(port, "GET", "/state")
    if status != 200:
        raise RuntimeError("Backend state endpoint did not return 200")
    value = json.loads(body)
    if set(value) != {"accepted_calls", "last_request_id"}:
        raise RuntimeError("Backend state endpoint returned an unexpected schema")
    return value


def _assert_denial(lab, phase, component, component_port, invalid_body, size_body,
                   backend_port, expected_count):
    before = _backend_state(backend_port)
    schema_status, schema_response = _request(component_port, "POST", "/infer", invalid_body)
    schema_result = {"status": schema_status, "response": json.loads(schema_response)}
    lab.check(phase, f"{component} rejects the benign schema-invalid typed object",
              schema_status == 422 and schema_result["response"] == {"status": "schema_invalid"},
              schema_result)
    after_schema = _backend_state(backend_port)
    lab.check(phase, f"Schema rejection at {component} did not reach the independent local backend",
              after_schema["accepted_calls"] == before["accepted_calls"] == expected_count,
              {"before": before["accepted_calls"], "after": after_schema["accepted_calls"]})

    size_status, size_response = _request(component_port, "POST", "/infer", size_body)
    size_result = {"status": size_status, "response": json.loads(size_response),
                   "body_bytes": len(size_body), "limit_bytes": 128}
    lab.check(phase, f"{component} rejects a valid typed object at 129 bytes",
              size_status == 413 and size_result["response"] == {"status": "body_too_large"}
              and len(size_body) == 129,
              size_result)
    after_size = _backend_state(backend_port)
    lab.check(phase, f"Body-size rejection at {component} did not reach the independent local backend",
              after_size["accepted_calls"] == expected_count,
              {"before": after_schema["accepted_calls"], "after": after_size["accepted_calls"]})


def run(lab):
    policy = json.loads((FIXTURES / "policy.json").read_text(encoding="utf-8"))
    valid = policy["fixtures"]["valid"]
    invalid = policy["fixtures"]["schema_invalid"]
    valid_body = json.dumps(valid, sort_keys=True, separators=(",", ":")).encode()
    valid["input"] += "x" * (policy["max_body_bytes"] - len(valid_body))
    valid_body = json.dumps(valid, sort_keys=True, separators=(",", ":")).encode()
    invalid_body = json.dumps(invalid, sort_keys=True, separators=(",", ":")).encode()
    if len(valid_body) != policy["max_body_bytes"]:
        lab.block("The benign valid fixture must match its exact declared fixture threshold")
    oversized = {"request_id": "fixture-0902-003-size", "input": ""}
    while len(json.dumps(oversized, sort_keys=True, separators=(",", ":")).encode()) < 129:
        oversized["input"] += "x"
    size_body = json.dumps(oversized, sort_keys=True, separators=(",", ":")).encode()
    if len(size_body) != policy["max_body_bytes"] + 1:
        lab.block("Could not construct the exact one-byte-over benign typed fixture")

    config = lab.create(_config_map(policy))
    if config.get("immutable") is not True:
        lab.block("Case fixture ConfigMap did not persist as immutable")
    for resource in _resources():
        lab.create(resource)
    lab.kubectl("rollout", "status", f"deployment/{APP}", "--timeout=180s", timeout=190)

    forwards = []
    try:
        gateway, gateway_port = _forward(lab, f"{APP}-gateway", 8080)
        forwards.append(gateway)
        model, model_port = _forward(lab, f"{APP}-model", 9001)
        forwards.append(model)
        backend, backend_port = _forward(lab, f"{APP}-backend", 9002)
        forwards.append(backend)
        for count, (body, request_id) in enumerate(
            ((invalid_body, invalid["request_id"]), (size_body, oversized["request_id"])), start=1
        ):
            status, marker = _request(gateway_port, "POST", "/infer", body)
            state = _backend_state(backend_port)
            lab.check("red", f"Disabled fixture checks forward the ordinary request {count} to the recorder",
                      status == 200 and marker == policy["accepted_marker"].encode()
                      and state == {"accepted_calls": count, "last_request_id": request_id},
                      {"http_status": status, "backend": state})
    finally:
        _stop_forwards(forwards)

    lab.kubectl("set", "env", f"deployment/{APP}", "FIXTURE_ENFORCE=true")
    lab.kubectl("rollout", "status", f"deployment/{APP}", "--timeout=100s", timeout=110)

    forwards = []
    try:
        gateway, gateway_port = _forward(lab, f"{APP}-gateway", 8080)
        forwards.append(gateway)
        model, model_port = _forward(lab, f"{APP}-model", 9001)
        forwards.append(model)
        backend, backend_port = _forward(lab, f"{APP}-backend", 9002)
        forwards.append(backend)
        initial = _backend_state(backend_port)
        lab.check("positive", "Case-owned backend recorder starts with zero accepted requests",
                  initial == {"accepted_calls": 0, "last_request_id": None}, initial)

        _assert_denial(lab, "green", "gateway", gateway_port, invalid_body, size_body,
                       backend_port, 0)
        gateway_status, gateway_marker = _request(gateway_port, "POST", "/infer", valid_body)
        after_gateway = _backend_state(backend_port)
        gateway_ok = (gateway_status == 200 and gateway_marker == policy["accepted_marker"].encode()
                      and after_gateway == {"accepted_calls": 1,
                                            "last_request_id": valid["request_id"]})
        lab.check("green", "Gateway accepts the exact valid fixture, returns the exact marker, and records one backend call",
                  gateway_ok,
                  {"status": gateway_status, "marker_exact": gateway_marker == policy["accepted_marker"].encode(),
                   "backend": after_gateway})

        _assert_denial(lab, "green", "model", model_port, invalid_body, size_body,
                       backend_port, 1)
        model_status, model_marker = _request(model_port, "POST", "/infer", valid_body)
        after_model = _backend_state(backend_port)
        model_ok = (model_status == 200 and model_marker == policy["accepted_marker"].encode()
                    and after_model == {"accepted_calls": 2,
                                       "last_request_id": valid["request_id"]})
        lab.check("positive", "Model service independently enforces policy and accepts the exact valid fixture",
                  model_ok,
                  {"status": model_status, "marker_exact": model_marker == policy["accepted_marker"].encode(),
                   "backend": after_model})
    finally:
        _stop_forwards(forwards)

    (lab.evidence / "request-validation.json").write_text(
        json.dumps({"observations": lab.checks, "case_body_limit_bytes": policy["max_body_bytes"]},
                   indent=2, sort_keys=True) + "\n")


def _stop_forwards(forwards):
    for process in reversed(forwards):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
