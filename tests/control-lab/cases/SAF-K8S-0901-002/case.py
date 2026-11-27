"""Synthetic request-assignment and schema checks for SAF-K8S-0901-002."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
PROFILE_CASE = HERE.parent / "SAF-K8S-0502-002" / "case.py"
INSTALLS_CNI = True
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
    "One disposable two-node Kind v0.32.0 cluster on Kubernetes v1.36.1 runs the exact "
    "published SAF-K8S-0502-002 Cilium 1.20.5 WireGuard profile before this control's "
    "workloads are created. Its four profile assertions remain separate from this case's "
    "19 existing application assertions. One added Gloo path assertion requires a total "
    "of 24 matched checks. The Gloo workers are pinned to different nodes and an "
    "additional passive per-pair WireGuard counter check binds their real fixed collective "
    "to the cross-node Cilium tunnel. This demonstrates Cilium-managed cross-node traffic only. "
    "It does not demonstrate Gloo-native TLS, Gloo peer authentication, same-node encryption, "
    "production route coverage, or production identity governance. "
    "The cluster hosts two synthetic worker Pods, "
    "one observer Pod, and one case-owned ClusterIP aggregation mock. The mock has an "
    "Kubernetes TokenReview verification of audience-scoped Pod identities, an enrollment-to-round table, "
    "and accepts only a fixed v1 JSON schema with "
    "three finite numeric entries in [-0.05, 0.05] when enforcement is enabled. Red sends "
    "only harmless synthetic metadata and small numeric values: one enrolled worker on the "
    "wrong assigned round and one short numeric vector. Green repeats those requests after "
    "enforcement is enabled, then two assigned workers submit ordinary fixed vectors. An "
    "independent observer reads stable counters and the exact mock aggregate. The published HTTP slice uses no real model, "
    "external service, real identity, external credential, feed, or target. An additive CPU Gloo slice runs one fixed collective "
    "using PyTorch without model training. "
    "A separate observer Pod has a projected synthetic identity, reads counters, and is refused contribution as unenrolled. "
    "After those 14 checks, a paired fixture compares the same three fixed in-range synthetic values "
    "with anomaly screening disabled and enabled while schema and assignment checks stay enabled. "
    "After the 15 existing checks, an isolated TLS-only mock endpoint compares one fixed authenticated vector over verified TLS with cleartext refusal and a CA-trusted alternate-name certificate rejection."
)


def _load_profile_case():
    import importlib.util
    spec = importlib.util.spec_from_file_location("saf_0901_002_wireguard_profile", PROFILE_CASE)
    if spec is None or spec.loader is None:
        raise RuntimeError("published two-node WireGuard profile is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_kind(_lab, temporary):
    return _load_profile_case().prepare_kind(_lab, temporary)


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
    # Reuse the exact published two-node Cilium profile before creating any
    # 0901 workloads. It leaves WireGuard enabled for the subsequent Gloo path.
    _load_profile_case().run(lab)
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

    # Paired synthetic policy variants follow the original 14 checks. The same
    # authenticated worker Pod and Service submit the exact same fixed,
    # schema-valid vectors in screening-off mode and then screening-on mode.
    screening_keys = ("screen_benign_comparator", "screen_alert_quarantine", "screen_hard_deny")
    kubectl(lab, "-n", NAMESPACE, "delete", "pod", "aggregation", "--wait=true", timeout=40)
    apply(lab, pod_spec("aggregation", "aggregation", "screen-off"))
    screen_off_pod = wait_ready(lab, "aggregation")
    screen_off_service = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "service", SERVICE,
                                           "-o", "json").stdout)
    screen_off_slices, screen_off_endpoints = wait_ready_endpoint(
        lab, screen_off_pod.get("status", {}).get("podIP"))
    screen_off_endpoint_ok = (screen_off_service.get("spec", {}).get("clusterIP") == service_ip
                              and screen_off_endpoints == [screen_off_pod.get("status", {}).get("podIP")])
    screen_off_results = {}
    for key in screening_keys:
        result = exec_client(lab, "worker-a", "submit", key)
        screen_off_results[key] = result
        raw_write(lab.evidence / f"screening-off-{key}.raw.json", result)
    screen_off_status = read(lab, "status")
    screen_off_result = read(lab, "result")
    screen_off_log = kubectl(lab, "-n", NAMESPACE, "logs", "pod/aggregation").stdout
    (lab.evidence / "screening-off-aggregator.raw.jsonl").write_text(
        screen_off_log, encoding="utf-8")
    screen_off_events = [json.loads(line) for line in screen_off_log.splitlines() if line.strip()]
    raw_write(lab.evidence / "screening-off-independent-readback.raw.json", {
        "status": screen_off_status, "aggregate": screen_off_result})

    expected_screen_off_status = {
        "received_count": 3, "accepted_count": 3, "rejected_count": 0,
        "rejected_by_reason": {"schema": 0, "assignment": 0},
    }
    expected_screen_off_result = {"accepted_count": 3, "mean": [0.031667, -0.01, 0.0]}
    screen_off_bodies = {
        "screen_benign_comparator": {"request_id": "synthetic-screen-benign-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.025, -0.01, 0.0]},
        "screen_alert_quarantine": {"request_id": "synthetic-screen-alert-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.03, -0.01, 0.0]},
        "screen_hard_deny": {"request_id": "synthetic-screen-deny-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.04, -0.01, 0.0]},
    }
    screen_off_events_by_id = {row.get("request", {}).get("request_id"): row
                               for row in screen_off_events if isinstance(row.get("request"), dict)}
    expected_screen_off_responses = {key: {"http_status": 200,
        "response": {"status": "accepted"}} for key in screening_keys}
    screen_off_outcomes_match = all(
        screen_off_results[key].get("http_status") == expected["http_status"]
        and screen_off_results[key].get("response") == expected["response"]
        for key, expected in expected_screen_off_responses.items())
    screen_off_inputs_match = (len(screen_off_events) == 3 and len(screen_off_events_by_id) == 3
        and all(screen_off_events_by_id.get(body["request_id"], {}).get("request") == body
                and screen_off_events_by_id.get(body["request_id"], {}).get("authenticated_identity") == "worker-a"
                and screen_off_events_by_id.get(body["request_id"], {}).get("mode") == "screen-off"
                and screen_off_events_by_id.get(body["request_id"], {}).get("outcome") == {"status": "accepted"}
                for body in screen_off_bodies.values()))
    screen_off_readback_match = (screen_off_status == expected_screen_off_status
                                 and screen_off_result == expected_screen_off_result)
    screen_off_raw = {
        "scope": "Anomaly-screening-disabled counterfactual retaining schema and assignment enforcement, for the same three fixed vectors after the original 14 assertions.",
        "screening_pod_uid": screen_off_pod.get("metadata", {}).get("uid"),
        "screening_pod_ip": screen_off_pod.get("status", {}).get("podIP"),
        "same_service_endpoint": screen_off_endpoint_ok,
        "endpoint_slices": screen_off_slices,
        "request_results": screen_off_results,
        "authenticated_server_events": screen_off_events,
        "expected_bodies": screen_off_bodies,
        "exact_authenticated_inputs_match": screen_off_inputs_match,
        "independent_status": screen_off_status,
        "expected_status": expected_screen_off_status,
        "independent_aggregate": screen_off_result,
        "expected_aggregate": expected_screen_off_result,
        "outcomes_match": screen_off_outcomes_match,
        "readback_match": screen_off_readback_match,
    }
    raw_write(lab.evidence / "screening-off-policy.raw.json", screen_off_raw)

    # Replace the screening-off Pod with the screening policy. Counter state is
    # fresh while Service IP and authenticated client identities remain fixed.
    kubectl(lab, "-n", NAMESPACE, "delete", "pod", "aggregation", "--wait=true", timeout=40)
    apply(lab, pod_spec("aggregation", "aggregation", "screen"))
    screening_pod = wait_ready(lab, "aggregation")
    screen_service = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "service", SERVICE,
                                       "-o", "json").stdout)
    screen_slices, screen_endpoints = wait_ready_endpoint(
        lab, screening_pod.get("status", {}).get("podIP"))
    endpoint_ok = (screen_service.get("spec", {}).get("clusterIP") == service_ip
                   and screen_endpoints == [screening_pod.get("status", {}).get("podIP")])

    screening_results = {}
    for key in screening_keys:
        result = exec_client(lab, "worker-a", "submit", key)
        screening_results[key] = result
        raw_write(lab.evidence / f"screening-{key}.raw.json", result)
    screening_status = read(lab, "status")
    screening_result = read(lab, "result")
    screening_log = kubectl(lab, "-n", NAMESPACE, "logs", "pod/aggregation").stdout
    (lab.evidence / "screening-aggregator.raw.jsonl").write_text(
        screening_log, encoding="utf-8")
    screening_events = [json.loads(line) for line in screening_log.splitlines() if line.strip()]
    raw_write(lab.evidence / "screening-independent-readback.raw.json", {
        "status": screening_status, "aggregate": screening_result})

    expected_screening = {
        "screen_benign_comparator": {"http_status": 200,
            "response": {"status": "accepted", "score": 0.015}},
        "screen_alert_quarantine": {"http_status": 202,
            "response": {"status": "quarantined", "reason": "anomaly_alert", "score": 0.02}},
        "screen_hard_deny": {"http_status": 422,
            "response": {"status": "rejected", "reason": "anomaly_threshold", "score": 0.03}},
    }
    outcomes_match = all(
        screening_results[key].get("http_status") == expected["http_status"]
        and screening_results[key].get("response") == expected["response"]
        for key, expected in expected_screening.items())
    expected_bodies = {
        "screen_benign_comparator": {"request_id": "synthetic-screen-benign-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.025, -0.01, 0.0]},
        "screen_alert_quarantine": {"request_id": "synthetic-screen-alert-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.03, -0.01, 0.0]},
        "screen_hard_deny": {"request_id": "synthetic-screen-deny-01",
            "worker_id": "worker-a", "round_id": "round-7", "schema_version": "v1",
            "vector": [0.04, -0.01, 0.0]},
    }
    events_by_id = {row.get("request", {}).get("request_id"): row
                    for row in screening_events if isinstance(row.get("request"), dict)}
    inputs_match = (len(screening_events) == 3 and len(events_by_id) == 3
                    and all(events_by_id.get(body["request_id"], {}).get("request") == body
                            and events_by_id.get(body["request_id"], {}).get("authenticated_identity") == "worker-a"
                            and events_by_id.get(body["request_id"], {}).get("mode") == "screen"
                            and events_by_id.get(body["request_id"], {}).get("outcome")
                                == expected_screening[key]["response"]
                            for key, body in expected_bodies.items())
                    and all(all(abs(value) <= 0.05 for value in body["vector"])
                            for body in expected_bodies.values()))
    expected_screening_status = {
        "received_count": 3, "accepted_count": 1, "rejected_count": 1,
        "rejected_by_reason": {"schema": 0, "assignment": 0, "anomaly": 1},
        "quarantined_count": 1, "alerted_count": 1,
    }
    expected_screening_result = {"accepted_count": 1, "mean": [0.025, -0.01, 0.0]}
    readback_match = (screening_status == expected_screening_status
                      and screening_result == expected_screening_result)
    screening_raw = {
        "scope": "Paired screening-disabled and screening-enabled variants after the original 14 assertions; schema and assignment enforcement stay enabled and the same three fixed values come from one authenticated synthetic worker.",
        "screen_off_counterfactual": screen_off_raw,
        "screen_off_endpoint_same_service": screen_off_endpoint_ok,
        "screen_off_outcomes_match": screen_off_outcomes_match,
        "screen_off_exact_authenticated_inputs_match": screen_off_inputs_match,
        "screen_off_independent_status_and_aggregate_match": screen_off_readback_match,
        "baseline": [0.01, -0.01, 0.0],
        "score": "rounded maximum absolute coordinate deviation from the fixed baseline",
        "policy": {"accept_at_or_below": 0.015, "quarantine_and_alert_above": 0.015,
                   "deny_at_or_above": 0.03},
        "screening_pod_uid": screening_pod.get("metadata", {}).get("uid"),
        "screening_pod_ip": screening_pod.get("status", {}).get("podIP"),
        "service_cluster_ip_unchanged": screen_service.get("spec", {}).get("clusterIP") == service_ip,
        "one_ready_endpoint_is_screening_pod": screen_endpoints == [screening_pod.get("status", {}).get("podIP")],
        "endpoint_slices": screen_slices,
        "results": screening_results, "expected_results": expected_screening,
        "authenticated_server_events": screening_events,
        "expected_request_bodies": expected_bodies,
        "exact_authenticated_inputs_match": inputs_match,
        "independent_status": screening_status, "expected_status": expected_screening_status,
        "independent_aggregate": screening_result, "expected_aggregate": expected_screening_result,
        "status_and_aggregate_match": readback_match,
        "vectors_are_fixed_and_in_range": True,
        "external_targets_accessed": False,
        "real_model_or_training_used": False,
    }
    raw_write(lab.evidence / "screening-policy.raw.json", screening_raw)
    lab.check("positive",
              "The screen_off and screening variants receive the same benign in-range vectors; screening accepts the boundary comparator, alerts and quarantines the middle score, denies the hard threshold, and exposes only the accepted vector to independent readback",
              screen_off_endpoint_ok and screen_off_outcomes_match and screen_off_readback_match
                  and screen_off_inputs_match and endpoint_ok and outcomes_match and readback_match and inputs_match
                  and all(screen_off_bodies[key] == expected_bodies[key] for key in screening_keys),
              {"same_service_reaches_screen_off_variant": screen_off_endpoint_ok,
               "screen_off_counterfactual_accepts_all_three": screen_off_outcomes_match,
               "screen_off_independent_status_and_aggregate_match": screen_off_readback_match,
               "same_service_reaches_screening_variant": endpoint_ok,
               "benign_comparator_accepted": screening_results["screen_benign_comparator"].get("response")
                   == expected_screening["screen_benign_comparator"]["response"],
               "middle_score_quarantined_and_alerted": screening_results["screen_alert_quarantine"].get("response")
                   == expected_screening["screen_alert_quarantine"]["response"],
               "hard_score_denied": screening_results["screen_hard_deny"].get("response")
                   == expected_screening["screen_hard_deny"]["response"],
               "same_exact_bodies_in_both_variants": all(
                   screen_off_bodies[key] == expected_bodies[key] for key in screening_keys),
               "screen_off_exact_authenticated_inputs_match": screen_off_inputs_match,
               "exact_authenticated_inputs_match": inputs_match,
               "independent_status_and_aggregate_match": readback_match})

    from importlib.util import module_from_spec, spec_from_file_location

    tls_spec = spec_from_file_location("saf_0901_002_tls_channel", HERE / "tls_channel.py")
    tls_channel = module_from_spec(tls_spec)
    tls_spec.loader.exec_module(tls_channel)
    tls_channel.run_tls_channel(lab, HERE)

    # Run the CPU collective after the existing control checks.
    gloo_spec = spec_from_file_location("saf_0901_002_gloo_hook", HERE / "gloo_hook.py")
    gloo_hook = module_from_spec(gloo_spec)
    gloo_spec.loader.exec_module(gloo_hook)
    gloo_hook.run(lab, HERE)
