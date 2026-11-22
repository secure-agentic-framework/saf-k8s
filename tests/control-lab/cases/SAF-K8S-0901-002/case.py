"""Synthetic request-assignment and schema checks for SAF-K8S-0901-002."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0901-002"
SERVICE = "aggregation"
PORT = 8080
WORKER_LABEL = "saf-k8s.example/0901-002-role"
SCOPE = (
    "One disposable Kind cluster on Kubernetes v1.36.1 hosts two synthetic worker Pods, "
    "one observer Pod, and one case-owned ClusterIP aggregation mock. The mock has an "
    "Kubernetes TokenReview verification of audience-scoped Pod identities, an enrollment-to-round table, "
    "and accepts only a fixed v1 JSON schema with "
    "three finite numeric entries in [-0.05, 0.05] when enforcement is enabled. Red sends "
    "only harmless synthetic metadata and small numeric values: one enrolled worker on the "
    "wrong assigned round and one short numeric vector. Green repeats those requests after "
    "enforcement is enabled, then two assigned workers submit ordinary fixed vectors. An "
    "independent observer reads stable counters and the exact mock aggregate. No real model, "
    "training framework, external service, real identity, external credential, feed, or target is used. "
    "A separate authenticated observer can read counters and is refused ordinary contribution access."
)


def kubectl(lab, *args, timeout=35, allow_failure=False, **kwargs):
    return lab.kubectl(*args, timeout=timeout, allow_failure=allow_failure, **kwargs)


def apply(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace")
    args = ["-n", namespace] if namespace else []
    kubectl(lab, *args, "apply", "-f", "-", payload=json.dumps(obj))


def raw_write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected pinned kind v0.32.0, got {kind_version!r}")
    server = json.loads(kubectl(lab, "version", "-o", "json").stdout).get("serverVersion", {})
    version = server.get("gitVersion")
    lab.check("positive", "The API server is Kubernetes v1.36.1", version == "v1.36.1",
              {"kind_version": kind_version, "kubernetes_version": version})


def identities(lab):
    for name in ("aggregation", "worker-a", "worker-b", "observer"):
        apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": NAMESPACE}})
    reviewer = "saf-0901-002-token-reviewer"
    apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": reviewer}, "rules": [
                    {"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}
                ]})
    apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": reviewer},
                "subjects": [{"kind": "ServiceAccount", "name": "aggregation", "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": reviewer}})


def fixture_configmaps(lab):
    fixtures = HERE / "fixtures"
    aggregator = (fixtures / "aggregator.py").read_text(encoding="utf-8")
    client = (fixtures / "client.py").read_text(encoding="utf-8")
    requests = (fixtures / "requests.json").read_text(encoding="utf-8")
    for name, files in (("aggregator-code", {"aggregator.py": aggregator}),
                        ("worker-code", {"client.py": client, "requests.json": requests})):
        apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "namespace": NAMESPACE},
                    "data": files})


def pod_spec(name, role, mode=None):
    env = [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}]
    if mode is not None:
        env.append({"name": "ENFORCEMENT_MODE", "value": mode})
    code_config = "aggregator-code" if role == "aggregation" else "worker-code"
    mounts = [{"name": "case-code", "mountPath": "/case", "readOnly": True}]
    volumes = [{"name": "case-code", "configMap": {"name": code_config}}]
    if role != "aggregation":
        mounts.append({"name": "worker-identity", "mountPath": "/run/fixture-identity", "readOnly": True})
        volumes.append({"name": "worker-identity", "projected": {"sources": [
            {"serviceAccountToken": {"audience": "saf-fixture-0901-002", "expirationSeconds": 600, "path": "token"}}
        ]}})
    command = ["python3", "/case/aggregator.py"] if role == "aggregation" else ["python3", "-c", "import time; time.sleep(3600)"]
    container = {
        "name": "fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": command, "env": env,
        "ports": [{"name": "http", "containerPort": PORT}] if role == "aggregation" else [],
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": mounts,
    }
    if role == "aggregation":
        container["readinessProbe"] = {"httpGet": {"path": "/healthz", "port": PORT},
                                       "periodSeconds": 1}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {WORKER_LABEL: role, "app": "saf-0901-002"}},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": role == "aggregation",
            "terminationGracePeriodSeconds": 1, "serviceAccountName": name,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container],
            "volumes": volumes,
        },
    }


def wait_ready(lab, name, timeout=90):
    kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
            f"--timeout={timeout}s", timeout=timeout + 10)
    pod = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)
    containers = pod.get("spec", {}).get("containers", [])
    statuses = pod.get("status", {}).get("containerStatuses", [])
    good = (pod.get("status", {}).get("phase") == "Running" and len(containers) == 1
            and containers[0].get("image") == IMAGE and len(statuses) == 1
            and statuses[0].get("ready") is True)
    if not good:
        lab.block(f"Fixture pod {name} is not ready on the pinned image")
    return pod


def wait_ready_endpoint(lab, expected_ip, timeout=30):
    deadline = time.monotonic() + timeout
    last_slices = {"items": []}
    last_addresses = []
    while time.monotonic() < deadline:
        last_slices = json.loads(kubectl(
            lab, "-n", NAMESPACE, "get", "endpointslices", "-l",
            f"kubernetes.io/service-name={SERVICE}", "-o", "json").stdout)
        last_addresses = [ip for item in last_slices.get("items", [])
                          for endpoint in item.get("endpoints", [])
                          if endpoint.get("conditions", {}).get("ready")
                          for ip in endpoint.get("addresses", [])]
        if last_addresses == [expected_ip]:
            return last_slices, last_addresses
        time.sleep(0.25)
    return last_slices, last_addresses


def exec_client(lab, pod, operation, key):
    result = kubectl(lab, "-n", NAMESPACE, "exec", f"pod/{pod}", "--",
                     "python3", "/case/client.py", operation, key,
                     timeout=12, allow_failure=True)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block(f"Fixture client {pod}/{key} returned no bounded JSON result")


def submit(lab, evidence, phase, pod, key, expected_status, expected_response):
    observed = exec_client(lab, pod, "submit", key)
    raw_write(evidence / f"{phase}-{key}.raw.json", observed)
    response = observed.get("response", {})
    matched = (observed.get("http_status") == expected_status
               and response == expected_response)
    lab.check(phase, f"{key} has the expected mock aggregation outcome", matched,
              {"request_key": key, "http_status": observed.get("http_status"),
               "response": response, "expected_status": expected_status,
               "expected_response": expected_response})


def read(lab, key):
    return exec_client(lab, "observer", "read", key)


def run(lab):
    verify_platform(lab)
    apply(lab, {"apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": NAMESPACE,
                             "labels": {"saf-k8s.example/0901-002": "synthetic"}}})
    identities(lab)
    fixture_configmaps(lab)

    # One stable ClusterIP backs the sole aggregation endpoint across both phases.
    apply(lab, {"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": SERVICE, "namespace": NAMESPACE},
                "spec": {"type": "ClusterIP", "selector": {WORKER_LABEL: "aggregation"},
                         "ports": [{"name": "http", "protocol": "TCP", "port": PORT,
                                    "targetPort": PORT}]}})
    apply(lab, pod_spec("aggregation", "aggregation", "off"))
    for name, role in (("worker-a", "worker"), ("worker-b", "worker"), ("observer", "observer")):
        apply(lab, pod_spec(name, role))
    aggregation = wait_ready(lab, "aggregation")
    for name in ("worker-a", "worker-b", "observer"):
        wait_ready(lab, name)

    service = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "service", SERVICE,
                                  "-o", "json").stdout)
    service_ip = service.get("spec", {}).get("clusterIP")
    if not service_ip or service_ip == "None":
        lab.block("The case-owned aggregator Service has no ClusterIP")
    slices, endpoints = wait_ready_endpoint(lab, aggregation.get("status", {}).get("podIP"))
    if len(endpoints) != 1 or endpoints[0] != aggregation.get("status", {}).get("podIP"):
        lab.block("The case-owned aggregation Service does not resolve to exactly its mock Pod")

    # Red baseline: only safe fixed values, with assignment/schema enforcement disabled.
    submit(lab, lab.evidence, "red", "worker-a", "wrong_assignment", 200,
           {"status": "accepted"})
    submit(lab, lab.evidence, "red", "worker-a", "wrong_schema", 200,
           {"status": "accepted"})
    submit(lab, lab.evidence, "red", "worker-a", "outside_range", 200, {"status": "accepted"})
    baseline_log = kubectl(lab, "-n", NAMESPACE, "logs", "pod/aggregation").stdout
    (lab.evidence / "baseline-aggregator.raw.jsonl").write_text(baseline_log, encoding="utf-8")

    # Replace only the mock Pod. Service ClusterIP and all synthetic clients remain fixed.
    kubectl(lab, "-n", NAMESPACE, "delete", "pod", "aggregation", "--wait=true", timeout=40)
    apply(lab, pod_spec("aggregation", "aggregation", "enforce"))
    enforced_aggregation = wait_ready(lab, "aggregation")
    service_after = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "service", SERVICE,
                                        "-o", "json").stdout)
    slices_after, endpoints_after = wait_ready_endpoint(
        lab, enforced_aggregation.get("status", {}).get("podIP"))
    stable_endpoint = (service_after.get("spec", {}).get("clusterIP") == service_ip
                       and endpoints_after == [enforced_aggregation.get("status", {}).get("podIP")])
    lab.check("positive", "The same case-owned Service reaches the replacement mock Pod",
              stable_endpoint,
              {"cluster_ip_unchanged": service_after.get("spec", {}).get("clusterIP") == service_ip,
               "one_ready_endpoint_is_current_mock": endpoints_after == [enforced_aggregation.get("status", {}).get("podIP")]})

    submit(lab, lab.evidence, "green", "worker-a", "wrong_assignment", 422,
           {"reason": "assignment", "status": "rejected"})
    submit(lab, lab.evidence, "green", "worker-a", "wrong_schema", 422,
           {"reason": "schema", "status": "rejected"})
    submit(lab, lab.evidence, "green", "worker-a", "outside_range", 422,
           {"reason": "schema", "status": "rejected"})
    submit(lab, lab.evidence, "green", "observer", "unenrolled_observer", 403,
           {"reason": "not_enrolled", "status": "rejected"})
    submit(lab, lab.evidence, "positive", "worker-a", "worker_a_valid", 200,
           {"status": "accepted"})
    submit(lab, lab.evidence, "positive", "worker-b", "worker_b_valid", 200,
           {"status": "accepted"})

    first_status = read(lab, "status")
    second_status = read(lab, "status")
    raw_write(lab.evidence / "accounting.raw.json", {
        "first_observer_read": first_status, "second_observer_read": second_status})
    expected_status = {"received_count": 5, "accepted_count": 2, "rejected_count": 3,
                       "rejected_by_reason": {"assignment": 1, "schema": 2}}
    lab.check("positive", "Independent status reads show stable accepted and rejected accounting",
              first_status == expected_status and second_status == expected_status,
              {"first": first_status, "second": second_status,
               "expected": expected_status, "reads_match": first_status == second_status})

    result = read(lab, "result")
    raw_write(lab.evidence / "mock-result.raw.json", result)
    expected_result = {"accepted_count": 2, "mean": [0.015, -0.01, 0.01]}
    lab.check("positive", "Observer reads exact aggregate independently of worker receipts",
              result == expected_result,
              {"observer_result": result, "expected_result": expected_result,
               "read_by_observer_pod": True, "derived_from_submit_responses": False})

    final_log = kubectl(lab, "-n", NAMESPACE, "logs", "pod/aggregation").stdout
    (lab.evidence / "enforced-aggregator.raw.jsonl").write_text(final_log, encoding="utf-8")
    receipt = [json.loads(line) for line in final_log.splitlines() if line.strip()]
    auth_events = {row["request"]["request_id"]: row["authenticated_identity"]
                   for row in receipt if "request" in row and row["outcome"] == {"status": "accepted"}}
    unenrolled = [row for row in receipt if row.get("outcome") == "not_enrolled"]
    lab.check("positive", "Accepted workers and rejected unassigned observer have verified Kubernetes identities",
              auth_events == {"synthetic-valid-worker-a-01": "worker-a", "synthetic-valid-worker-b-01": "worker-b"}
              and unenrolled == [{"authenticated_identity": "observer", "outcome": "not_enrolled"}],
              {"accepted_principals": auth_events, "unenrolled_principals": unenrolled})
    raw_write(lab.evidence / "workloads.raw.json", {
        "kind_node_image": NODE_IMAGE,
        "worker_image": IMAGE, "service": service,
        "service_after_baseline_replacement": service_after,
        "pods": {name: json.loads(kubectl(lab, "-n", NAMESPACE, "get", "pod", name,
                                           "-o", "json").stdout)
                 for name in ("aggregation", "worker-a", "worker-b", "observer")},
        "endpoint_slice_before_replacement": slices,
        "endpoint_slice_after_replacement": slices_after,
    })
    raw_write(lab.evidence / "case-scope.json", {
        "control": "SAF-K8S-0901-002", "scope": SCOPE,
        "service_cluster_ip": service_ip, "aggregation_endpoint_pod_ip": endpoints[0],
        "schema_version": "v1", "vector_length": 3, "allowed_component_range": [-0.05, 0.05],
        "synthetic_worker_assignments": {"worker-a": "round-7", "worker-b": "round-7"},
        "external_targets_accessed": False, "secrets_collected": False,
        "real_model_or_training_used": False,
    })
