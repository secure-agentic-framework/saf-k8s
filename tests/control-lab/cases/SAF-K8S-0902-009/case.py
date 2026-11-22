"""Demonstrate one synthetic, nonstreaming response filter and byte cap."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-0902-009"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
PORT = 8080
SOURCE_PORT = 8081
SERVICE = "saf-0902-009-filter"
SOURCE = "saf-0902-009-source"
CLIENT = "saf-0902-009-client"
FILTER_CONFIG = "saf-0902-009-code"
MAX_OUTPUT_BYTES = 96
LABEL_CONTROL = "saf-k8s.example/control"
SCOPE = (
    "One disposable Kind v1.36.1 cluster and one namespace; one fixture-only, local, "
    "nonstreaming HTTP response source; one response-filter Pod; and an independent "
    "client Pod. The case compares the same fixture response through the same Service "
    "with the filter disabled and enabled, checks exact redaction, an exact 96-byte "
    "body cap, and one intended exact response. It does not exercise a model, a serving "
    "framework, gRPC, streaming, batch inference, real PII or training data, production "
    "rules, model-level safety, or external targets."
)


def _fixture():
    value = json.loads((FIXTURES / "response-fixture.json").read_text(encoding="utf-8"))
    if value.get("fixture_only") is not True:
        raise ValueError("response fixture must be marked fixture_only")
    private = value.get("private_dummy_marker")
    public = value.get("public_marker")
    if not isinstance(private, str) or not private.startswith("SYNTHETIC-PRIVATE-DUMMY-"):
        raise ValueError("private marker must be a fixture-designated synthetic dummy")
    if not isinstance(public, str) or not public.startswith("SAF-0902-009-PUBLIC-"):
        raise ValueError("public marker is outside the fixed fixture namespace")
    expected = value["response_body"]
    if private not in expected or public not in expected:
        raise ValueError("the response fixture must contain its exact public and dummy markers")
    if len(value["over_cap_body"].encode("utf-8")) != MAX_OUTPUT_BYTES + 1:
        raise ValueError("over-cap fixture must be exactly one byte above the configured cap")
    if len(value["at_cap_body"].encode("utf-8")) != MAX_OUTPUT_BYTES:
        raise ValueError("at-cap fixture must be exactly the configured byte limit")
    if len(expected.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("sensitive fixture response must fit the cap before redaction")
    return value


def _labels(role):
    return {LABEL_CONTROL: CONTROL_ID, "saf-k8s.example/role": role,
            "saf-k8s.example/fixture": "synthetic"}


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def _wait_pod(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)
    pod = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    if pod.get("metadata", {}).get("labels", {}).get(LABEL_CONTROL) != CONTROL_ID:
        lab.block(f"Pod {name} is not owned by this case")
    return pod


def _wait_endpoint(lab, service, pod):
    end = time.monotonic() + 20
    expected = [pod["status"]["podIP"]]
    while time.monotonic() < end:
        slices = json.loads(lab.kubectl("get", "endpointslices", "-l",
                          f"kubernetes.io/service-name={service}", "-o", "json").stdout)
        observed = [address for item in slices["items"] for endpoint in item.get("endpoints", [])
                    if endpoint.get("conditions", {}).get("ready") for address in endpoint["addresses"]]
        if observed == expected:
            return
        time.sleep(0.4)
    lab.block("The Service did not converge to its exact owned Ready endpoint")


def _pod(name, role, code, command, *, env=None, port=None, readiness=None):
    container = {
        "name": role, "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": command,
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "volumeMounts": [{"name": "case", "mountPath": "/case", "readOnly": True}],
    }
    if env:
        container["env"] = [{"name": key, "value": value} for key, value in env.items()]
    if port:
        container["ports"] = [{"name": "http", "containerPort": port}]
    if readiness:
        container["readinessProbe"] = readiness
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels(role)},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container],
            "volumes": [{"name": "case", "configMap": {
                "name": FILTER_CONFIG, "items": [{"key": f"{code}.py", "path": f"{code}.py"},
                                                    {"key": "response-fixture.json",
                                                     "path": "response-fixture.json"}]}}],
        },
    }


def _create_gateway(lab, enabled):
    gateway = _pod(
        SERVICE, "response-filter", "gateway", ["python", "/case/gateway.py"],
        env={"SAF_FILTER_ENABLED": "true" if enabled else "false",
             "SAF_SOURCE_URL": f"http://{SOURCE}:{SOURCE_PORT}",
             "SAF_OUTPUT_CAP_BYTES": str(MAX_OUTPUT_BYTES)},
        port=PORT, readiness={"httpGet": {"path": "/healthz", "port": "http"},
                              "periodSeconds": 2, "failureThreshold": 20},
    )
    _apply(lab, gateway)
    return _wait_pod(lab, SERVICE)


def _client_call(lab, path):
    result = lab.kubectl(
        "exec", CLIENT, "--", "python", "/case/client.py",
        f"http://{SERVICE}:{PORT}{path}", timeout=30,
    )
    observed = json.loads(result.stdout)
    if set(observed) != {"status", "body", "body_bytes"}:
        lab.block("Independent client returned an unexpected evidence schema")
    return observed


def _write_raw(lab, name, value):
    path = lab.evidence / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected Kind v0.32.0, observed {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    version = server.get("gitVersion")
    lab.check("positive", "The disposable API server reports Kubernetes v1.36.1",
              version == "v1.36.1",
              {"kind_version": kind_version, "kubernetes_version": version,
               "kind_node_image": NODE_IMAGE})


def run(lab):
    _verify_platform(lab)
    fixture = _fixture()
    lab.kubectl("create", "configmap", FILTER_CONFIG,
                f"--from-file=response-fixture.json={FIXTURES / 'response-fixture.json'}",
                f"--from-file=source.py={FIXTURES / 'source.py'}",
                f"--from-file=gateway.py={FIXTURES / 'gateway.py'}",
                f"--from-file=client.py={FIXTURES / 'client.py'}")
    # The shared ConfigMap key is deliberately projected to each process filename.
    # Source's key name is source.py; gateway.py and client.py are exact reviewed files.
    source_pod = _pod(
        SOURCE, "fixture-source", "source", ["python", "/case/source.py"],
        port=SOURCE_PORT,
        readiness={"tcpSocket": {"port": SOURCE_PORT}, "periodSeconds": 2,
                   "failureThreshold": 20},
    )
    _apply(lab, source_pod)
    source = _wait_pod(lab, SOURCE)
    _apply(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SOURCE, "namespace": NAMESPACE,
                     "labels": {LABEL_CONTROL: CONTROL_ID}},
        "spec": {"type": "ClusterIP", "selector": _labels("fixture-source"),
                 "ports": [{"name": "http", "port": SOURCE_PORT,
                            "targetPort": SOURCE_PORT, "protocol": "TCP"}]},
    })
    client_pod = _pod(CLIENT, "independent-client", "client", ["python", "-m", "http.server"])
    # The client is a dormant, separate Pod; calls execute its fixed fixture client script.
    client_pod["spec"]["containers"][0]["command"] = ["python", "-c", "import time; time.sleep(3600)"]
    _apply(lab, client_pod)
    _wait_pod(lab, CLIENT)

    _apply(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE,
                     "labels": {LABEL_CONTROL: CONTROL_ID}},
        "spec": {"type": "ClusterIP", "selector": _labels("response-filter"),
                 "ports": [{"name": "http", "port": PORT,
                            "targetPort": PORT, "protocol": "TCP"}]},
    })
    _wait_endpoint(lab, SOURCE, source)
    first_pod = _create_gateway(lab, enabled=False)
    _wait_endpoint(lab, SERVICE, first_pod)
    first_service = json.loads(lab.kubectl("get", "service", SERVICE, "-o", "json").stdout)

    fixture_raw = _client_call(lab, "/fixture")
    over_cap_raw = _client_call(lab, "/over-cap")
    baseline_ok = (
        fixture_raw["status"] == 200
        and fixture_raw["body"] == fixture["response_body"]
        and fixture_raw["body_bytes"] == len(fixture["response_body"].encode("utf-8"))
    )
    lab.check("red", "Without the response rule, the independent client receives the exact known fixture",
              baseline_ok, fixture_raw)
    baseline_cap_ok = (
        over_cap_raw["status"] == 200
        and over_cap_raw["body"] == fixture["over_cap_body"]
        and over_cap_raw["body_bytes"] == MAX_OUTPUT_BYTES + 1
    )
    lab.check("red", "With the rule disabled, the same path returns the fixture's 97-byte comparator",
              baseline_cap_ok, over_cap_raw)

    # Preserve the same Service and client. Replace only the case-owned filter Pod.
    lab.kubectl("delete", "pod", SERVICE, "--wait=true", timeout=40)
    second_pod = _create_gateway(lab, enabled=True)
    _wait_endpoint(lab, SERVICE, second_pod)
    second_service = json.loads(lab.kubectl("get", "service", SERVICE, "-o", "json").stdout)
    same_service = first_service["metadata"]["uid"] == second_service["metadata"]["uid"]
    changed_pod = first_pod["metadata"]["uid"] != second_pod["metadata"]["uid"]
    lab.check("positive", "The same Service selects the independently observed replacement filter",
              same_service and changed_pod, {"service_unchanged": same_service, "filter_replaced": changed_pod})
    redacted = _client_call(lab, "/fixture")
    expected_redacted = fixture["response_body"].replace(
        fixture["private_dummy_marker"], fixture["redaction_token"]
    )
    green_ok = (
        redacted["status"] == 200
        and redacted["body"] == expected_redacted
        and fixture["public_marker"] in redacted["body"]
        and fixture["private_dummy_marker"] not in redacted["body"]
        and redacted["body_bytes"] == len(expected_redacted.encode("utf-8"))
        and redacted["body_bytes"] <= MAX_OUTPUT_BYTES
    )
    lab.check("green", "The enabled rule redacts only the designated dummy marker and preserves public output",
              green_ok, redacted)

    intended = _client_call(lab, "/intended")
    intended_ok = (intended["status"] == 200
                   and intended["body"] == fixture["intended_output"]
                   and intended["body_bytes"] == len(fixture["intended_output"].encode("utf-8")))
    lab.check("positive", "An intended short fixture response returns exactly through the enabled filter",
              intended_ok, intended)

    at_cap = _client_call(lab, "/at-cap")
    at_cap_ok = (at_cap["status"] == 200
                 and at_cap["body"] == fixture["at_cap_body"]
                 and at_cap["body_bytes"] == MAX_OUTPUT_BYTES)
    lab.check("positive", "A fixture response exactly at the 96-byte limit returns unchanged",
              at_cap_ok, at_cap)

    capped = _client_call(lab, "/over-cap")
    expected_denial = fixture["cap_denial_body"]
    cap_ok = (capped["status"] == 413 and capped["body"] == expected_denial
              and capped["body_bytes"] == len(expected_denial.encode("utf-8"))
              and capped["body_bytes"] <= MAX_OUTPUT_BYTES)
    lab.check("green", "The enabled rule denies a response one byte above its exact 96-byte cap",
              cap_ok, capped)

    _write_raw(lab, "response-filter-observations.raw.json", {
        "control_id": CONTROL_ID, "fixture_only": True,
        "kind_node_image": NODE_IMAGE, "workload_image": PYTHON_IMAGE,
        "output_cap_bytes": MAX_OUTPUT_BYTES,
        "baseline_filter_enabled": False, "enforced_filter_enabled": True,
        "same_source_service": SOURCE, "same_gateway_service": SERVICE,
        "independent_client_pod": CLIENT,
        "observations": {"baseline_fixture": fixture_raw,
                         "baseline_over_cap": over_cap_raw,
                         "redacted_fixture": redacted,
                         "intended_output": intended, "at_cap_output": at_cap,
                         "over_cap_denial": capped},
    })
    _write_raw(lab, "response-filter-workloads.raw.json", {
        "source_pod": json.loads(lab.kubectl("get", "pod", SOURCE, "-o", "json").stdout),
        "gateway_pod": json.loads(lab.kubectl("get", "pod", SERVICE, "-o", "json").stdout),
        "client_pod": json.loads(lab.kubectl("get", "pod", CLIENT, "-o", "json").stdout),
        "services": [json.loads(lab.kubectl("get", "service", name, "-o", "json").stdout)
                     for name in (SOURCE, SERVICE)],
    })
