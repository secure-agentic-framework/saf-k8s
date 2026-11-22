"""Verify bounded per-model authorization on two local synthetic endpoints."""
import json
from pathlib import Path
import secrets
import tempfile
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0902-008"
NAMESPACE = "saf-0902-008"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PORT = 8080
GATEWAY = "fixture-gateway"
GATEWAY_SERVICE = "inference-gateway"
POLICY = {
    "identities": {
        "synthetic-client-a": ["model-alpha"],
        "synthetic-client-b": ["model-beta"],
    }
}
MODELS = {
    "model-alpha": {"marker": "SAF-SYNTHETIC-INFERENCE-ALPHA-0902-008"},
    "model-beta": {"marker": "SAF-SYNTHETIC-INFERENCE-BETA-0902-008"},
}
SCENARIOS = {
    "red-absent": ("model-alpha", None, 200, "SAF-SYNTHETIC-INFERENCE-ALPHA-0902-008"),
    "red-wrong-model": ("model-beta", "synthetic-client-a", 200,
                        "SAF-SYNTHETIC-INFERENCE-BETA-0902-008"),
    "green-absent": ("model-alpha", None, 401, "authentication-required"),
    "green-expired": ("model-alpha", "synthetic-client-a", 401, "authentication-required"),
    "green-wrong-model": ("model-beta", "synthetic-client-a", 403, "model-not-authorized"),
    "positive-alpha": ("model-alpha", "synthetic-client-a", 200,
                       "SAF-SYNTHETIC-INFERENCE-ALPHA-0902-008"),
    "positive-beta": ("model-beta", "synthetic-client-b", 200,
                      "SAF-SYNTHETIC-INFERENCE-BETA-0902-008"),
}
PROBE_OBSERVATIONS = []
SCOPE = (
    "One disposable Kind v1.36.1 cluster; one local fixture gateway; two fixed synthetic identities; "
    "and two case-owned model mock endpoints. An ephemeral per-run HS256 test key signs short-lived "
    "fixture tokens for only those fixed identity/model grants. Identical ordinary fixed GETs to two "
    "owned paths are observed in an open red baseline, then with gateway verification/enforcement, "
    "plus one positive request per authorized identity. Gateway and independent backend event logs "
    "use fixed event IDs and contain no tokens or authorization headers. No real issuer, ingress, "
    "feed, target, model, credential, or user data is used."
)


def apply_json(lab, resource):
    namespace = resource.get("metadata", {}).get("namespace")
    args = ["-n", namespace] if namespace else []
    lab.kubectl(*args, "apply", "-f", "-", payload=json.dumps(resource))


def json_kubectl(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def configmap_resource():
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "fixture-code", "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control": CONTROL_ID,
                                "saf-k8s.example/data": "synthetic"}},
        "immutable": True,
        "data": {
            "gateway.py": (HERE / "fixtures" / "gateway.py").read_text(encoding="utf-8"),
            "backend.py": (HERE / "fixtures" / "backend.py").read_text(encoding="utf-8"),
            "probe.py": (HERE / "fixtures" / "probe.py").read_text(encoding="utf-8"),
            "policy.json": json.dumps(POLICY, sort_keys=True),
        },
    }


def pod_base(name, command, ports, mounts, *, env=None, mode=None):
    labels = {"saf-k8s.example/control": CONTROL_ID,
              "saf-k8s.example/app": name, "saf-k8s.example/data": "synthetic"}
    if mode:
        labels["saf-k8s.example/gateway-mode"] = mode
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "fsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": name, "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": command, "ports": ports,
                "readinessProbe": {"tcpSocket": {"port": ports[0]["containerPort"]},
                                   "periodSeconds": 2, "timeoutSeconds": 1},
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                "env": env or [], "volumeMounts": mounts,
            }],
            "volumes": [
                {"name": "fixture-code", "configMap": {"name": "fixture-code"}},
                {"name": "test-key", "secret": {"secretName": "ephemeral-test-key",
                                                    "defaultMode": 288}},
            ],
        },
    }


def fixture_pods(mode):
    code_mount = {"name": "fixture-code", "mountPath": "/case", "readOnly": True}
    key_mount = {"name": "test-key", "mountPath": "/run/test-key", "readOnly": True}
    gateway = pod_base(
        GATEWAY, ["python", "-B", "/case/gateway.py"],
        [{"name": "http", "containerPort": PORT}], [code_mount, key_mount],
        env=[{"name": "GATEWAY_MODE", "value": mode}], mode=mode)
    client = pod_base(
        "fixture-client", ["python", "-B", "-m", "http.server", "8082"],
        [{"name": "unused", "containerPort": 8082}], [code_mount, key_mount])
    client_container = client["spec"]["containers"][0]
    client_container["command"] = ["python", "-B", "-c", "import time; time.sleep(300)"]
    client_container.pop("readinessProbe")
    backends = []
    for model, metadata in MODELS.items():
        backend = pod_base(
            model, ["python", "-B", "/case/backend.py"],
            [{"name": "http", "containerPort": 8081}], [code_mount],
            env=[{"name": "FIXTURE_MODEL", "value": model},
                 {"name": "FIXTURE_MARKER", "value": metadata["marker"]}])
        # Backends do not need the ephemeral verifier key.
        backend["spec"]["volumes"] = [backend["spec"]["volumes"][0]]
        backends.append(backend)
    return [gateway, client, *backends]


def wait_ready(lab, pod):
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{pod}",
                 "--timeout=90s", timeout=100)


def service_resource(name, selector, port, target_port):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"saf-k8s.example/control": CONTROL_ID}},
            "spec": {"type": "ClusterIP", "selector": selector,
                     "ports": [{"name": "http", "protocol": "TCP", "port": port,
                                "targetPort": target_port}]}}


def probe(lab, scenario):
    output = lab.kubectl(
        "-n", NAMESPACE, "exec", "pod/fixture-client", "--", "python", "-B",
        "/case/probe.py", scenario, f"http://{GATEWAY_SERVICE}:{PORT}",
        timeout=15, allow_failure=True)
    try:
        result = json.loads(output.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block(f"Scenario {scenario} produced no bounded fixture result")
    if result.get("event_id") != scenario:
        lab.block(f"Scenario {scenario} returned a mismatched event ID")
    PROBE_OBSERVATIONS.append(result)
    return result


def capture_logs(lab, name, phase, pod):
    logs = lab.kubectl("-n", NAMESPACE, "logs", f"pod/{pod}").stdout
    (lab.evidence / f"{phase}-{name}.raw.jsonl").write_text(logs, encoding="utf-8")
    try:
        return [json.loads(line) for line in logs.splitlines() if line.strip()]
    except json.JSONDecodeError:
        lab.block(f"{phase} {name} emitted a non-JSON log line")


def endpoint_receipt(lab):
    receipt = {}
    for name, pod in (("model-alpha", "model-alpha"), ("model-beta", "model-beta"),
                      (GATEWAY_SERVICE, GATEWAY)):
        service = json_kubectl(lab, "-n", NAMESPACE, "get", "service", name)
        slices = json_kubectl(lab, "-n", NAMESPACE, "get", "endpointslices",
                              "-l", f"kubernetes.io/service-name={name}")
        addresses = [address for item in slices.get("items", [])
                     for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready")
                     for address in endpoint.get("addresses", [])]
        if len(addresses) != 1:
            lab.block(f"Owned Service {name} does not have exactly one ready endpoint")
        receipt[name] = {"cluster_ip": service["spec"].get("clusterIP"),
                         "port": service["spec"]["ports"][0]["port"],
                         "pod": pod, "endpoint_addresses": addresses}
    return receipt


def verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    server_version = json_kubectl(lab, "version").get("serverVersion", {}).get("gitVersion")
    if not kind_version.startswith("kind v0.32.0") or server_version != "v1.36.1":
        lab.block(f"Expected kind v0.32.0 and Kubernetes v1.36.1; got {kind_version!r}, {server_version!r}")
    lab.check("positive", "Case is on the expected Kind and Kubernetes versions", True,
              {"kind_version": kind_version, "kubernetes_version": server_version,
               "node_image": NODE_IMAGE})


def run(lab):
    verify_platform(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    apply_json(lab, configmap_resource())
    # The secret bytes are generated per run and are never read back or written to evidence.
    with tempfile.NamedTemporaryFile() as key_file:
        key_file.write(secrets.token_bytes(32))
        key_file.flush()
        lab.kubectl("-n", NAMESPACE, "create", "secret", "generic", "ephemeral-test-key",
                    f"--from-file=key={key_file.name}", "-o", "name")
    services = [
        service_resource(GATEWAY_SERVICE, {"saf-k8s.example/app": GATEWAY}, PORT, PORT),
        service_resource("model-alpha", {"saf-k8s.example/app": "model-alpha"}, 8081, 8081),
        service_resource("model-beta", {"saf-k8s.example/app": "model-beta"}, 8081, 8081),
    ]
    for service in services:
        apply_json(lab, service)
    for resource in fixture_pods("open"):
        apply_json(lab, resource)
    for pod in (GATEWAY, "fixture-client", "model-alpha", "model-beta"):
        wait_ready(lab, pod)

    # Red is a deliberately open local baseline; same requests must fail closed below.
    red = [probe(lab, "red-absent"), probe(lab, "red-wrong-model")]
    for result in red:
        model, _identity, expected_status, expected_body = SCENARIOS[result["event_id"]]
        body_value = result.get("body", {}).get("result")
        if (result.get("status") == 200 and result.get("model") == model
                and body_value == expected_body):
            matched = True
        else:
            matched = False
        lab.check("red", f"Open baseline permits {result['event_id']} to reach its owned mock",
                  matched and expected_status == 200,
                  {"event_id": result["event_id"], "status": result.get("status"),
                   "model": result.get("model"), "fixed_mock_result": body_value})
    gateway_red = capture_logs(lab, "gateway", "red", GATEWAY)
    backend_red = {model: capture_logs(lab, model, "red", model)
                   for model in MODELS}

    # Replace the open gateway pod with an enforced instance; issuer key remains ephemeral.
    lab.kubectl("-n", NAMESPACE, "delete", "pod", GATEWAY, "--wait=true", timeout=45)
    enforced = fixture_pods("enforced")[0]
    apply_json(lab, enforced)
    wait_ready(lab, GATEWAY)
    (lab.evidence / "scope.json").write_text(json.dumps({
        "control": CONTROL_ID, "scope": SCOPE, "image": IMAGE, "node_image": NODE_IMAGE,
        "identities": POLICY["identities"], "models": MODELS,
        "gateway_mode": "red-open then green-enforced", "token_algorithm": "HS256",
        "token_key": "ephemeral-per-run; excluded from evidence", "request_method": "GET",
        "request_body": None, "outside_cluster_access": False,
        "real_credentials_or_data": False, "tokens_logged": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    green_absent = probe(lab, "green-absent")
    green_expired = probe(lab, "green-expired")
    green_wrong = probe(lab, "green-wrong-model")
    for result, decision in ((green_absent, "authentication-required"),
                             (green_expired, "authentication-required"),
                             (green_wrong, "model-not-authorized")):
        expected = SCENARIOS[result["event_id"]]
        passed = result.get("status") == expected[2] and result.get("body", {}).get("result") == decision
        lab.check("green", f"Enforced gateway denies {result['event_id']} before the backend",
                  passed, {"event_id": result["event_id"], "status": result.get("status"),
                           "decision": result.get("body", {}).get("result")})

    positives = [probe(lab, "positive-alpha"), probe(lab, "positive-beta")]
    for result in positives:
        _model, identity, status, marker = SCENARIOS[result["event_id"]]
        passed = (result.get("status") == status and result.get("identity") == identity
                  and result.get("body", {}).get("result") == marker
                  and result.get("body", {}).get("model") == _model)
        lab.check("positive", f"Authorized {identity} receives only its fixed {_model} mock response",
                  passed, {"event_id": result["event_id"], "identity": identity,
                           "model": result.get("model"), "status": result.get("status"),
                           "fixed_mock_result": result.get("body", {}).get("result")})

    gateway_live = capture_logs(lab, "gateway", "green-positive", GATEWAY)
    backend_live = {model: capture_logs(lab, model, "green-positive", model)
                    for model in MODELS}
    by_event_gateway = {record.get("event_id"): record for record in [*gateway_red, *gateway_live]}
    records_backend = [record for records in backend_live.values() for record in records]
    by_event_backend = {record.get("event_id"): record for record in records_backend}
    expected_gateway = {
        "red-absent": ("model-alpha", "unauthenticated", "allow", 200, 200),
        "red-wrong-model": ("model-beta", "unauthenticated", "allow", 200, 200),
        "green-absent": ("model-alpha", "unauthenticated", "deny-no-token", 401, None),
        "green-expired": ("model-alpha", "unauthenticated", "deny-invalid-token", 401, None),
        "green-wrong-model": ("model-beta", "synthetic-client-a", "deny-model", 403, None),
        "positive-alpha": ("model-alpha", "synthetic-client-a", "allow", 200, 200),
        "positive-beta": ("model-beta", "synthetic-client-b", "allow", 200, 200),
    }
    agreements = {}
    for event_id, expected in expected_gateway.items():
        gateway_record = by_event_gateway.get(event_id, {})
        backend_record = by_event_backend.get(event_id)
        expected_model, expected_principal, decision, status, backend_status = expected
        gateway_matches = (gateway_record.get("model") == expected_model
                           and gateway_record.get("principal") == expected_principal
                           and gateway_record.get("decision") == decision
                           and gateway_record.get("status") == status
                           and gateway_record.get("backend_status") == backend_status)
        backend_matches = ((backend_record is None) if backend_status is None else
                           backend_record is not None
                           and backend_record.get("model") == expected_model
                           and backend_record.get("result") == "served-fixed-marker")
        agreements[event_id] = {"gateway_matches": gateway_matches,
                                "backend_matches_expected": backend_matches,
                                "backend_observed": backend_record is not None}
    all_agree = (len(gateway_red) + len(gateway_live) == len(expected_gateway)
                 and len(records_backend) == len(by_event_backend) == 4
                 and sum(len(records) for records in backend_red.values()) == 2
                 and all(item["gateway_matches"] and item["backend_matches_expected"]
                         for item in agreements.values()))
    (lab.evidence / "requests.raw.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in PROBE_OBSERVATIONS),
        encoding="utf-8")
    lab.check("positive", "Gateway and independent backends agree on each allow or deny",
              all_agree, agreements)

    # Evidence excludes Secret objects, token strings, request headers and arbitrary bodies.
    pods = json_kubectl(lab, "-n", NAMESPACE, "get", "pods")
    pods["items"] = [{key: value for key, value in item.items() if key != "status"}
                     for item in pods.get("items", [])]
    services_raw = json_kubectl(lab, "-n", NAMESPACE, "get", "services")
    (lab.evidence / "owned-resources.raw.json").write_text(json.dumps({
        "pods_without_status": pods["items"], "services": services_raw["items"],
        "endpoints": endpoint_receipt(lab),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
