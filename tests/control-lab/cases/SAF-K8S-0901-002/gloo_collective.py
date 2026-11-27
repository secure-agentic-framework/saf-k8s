"""Bounded two-rank Gloo collective supplement for SAF-K8S-0901-002.

The CPU image is provided by the case runner. This module never builds or
downloads it. It reuses the published synthetic TokenReview aggregator and
fixed request vectors, then runs one actual two-Pod Gloo SUM reduction.
"""

import json
from pathlib import Path
import time


NAMESPACE = "saf-0901-002"
PORT = 29500
ENROLLMENT_SERVICE = "collective-enrollment"
RANK0_SERVICE = "collective-rank-zero"
ROLE_LABEL = "saf-k8s.example/0901-002-collective-role"
IDENTITY_LABEL = "saf-k8s.example/0901-002-collective-identity"
EXPECTED = [0.03, -0.02, 0.02]
RANKS = {"worker-a": 0, "worker-b": 1}
REQUEST_KEYS = {"worker-a": "worker_a_valid", "worker-b": "worker_b_valid"}
EXPECTED_INPUTS = {
    "worker-a": [0.01, -0.02, 0.03],
    "worker-b": [0.02, 0.0, -0.01],
}


def _kubectl(lab, *args, **kwargs):
    return lab.kubectl(*args, timeout=kwargs.pop("timeout", 35), **kwargs)


def _apply(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace")
    args = ["-n", namespace] if namespace else []
    _kubectl(lab, *args, "apply", "-f", "-", payload=json.dumps(obj))


def _raw(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pod(name, identity, image):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {ROLE_LABEL: "rank-zero" if identity == "worker-a" else "rank-one",
                                IDENTITY_LABEL: identity}},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": identity,
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "collective", "image": image, "imagePullPolicy": "Never",
                "command": ["python3", "/case/gloo_worker.py"],
                "env": [
                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                    {"name": "HOME", "value": "/tmp"},
                    {"name": "TMPDIR", "value": "/tmp"},
                    {"name": "OMP_NUM_THREADS", "value": "1"},
                    {"name": "MKL_NUM_THREADS", "value": "1"},
                    {"name": "FIXTURE_WORKER_ID", "value": identity},
                    {"name": "ENROLLMENT_URL", "value":
                     f"http://{ENROLLMENT_SERVICE}.{NAMESPACE}.svc.cluster.local:8080"},
                    {"name": "RANK_ZERO_URL", "value":
                     f"tcp://{RANK0_SERVICE}.{NAMESPACE}.svc.cluster.local:{PORT}"},
                ],
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "500m", "memory": "1Gi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [
                    {"name": "code", "mountPath": "/case", "readOnly": True},
                    {"name": "identity", "mountPath": "/run/fixture-identity", "readOnly": True},
                    {"name": "tmp", "mountPath": "/tmp"},
                ],
            }],
            "volumes": [
                {"name": "code", "configMap": {"name": "gloo-worker-code"}},
                {"name": "identity", "projected": {"sources": [{
                    "serviceAccountToken": {"audience": "saf-fixture-0901-002",
                                             "expirationSeconds": 600, "path": "token"}
                }]}},
                {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
            ],
        },
    }


def _service(name, selector):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "spec": {"type": "ClusterIP", "selector": selector,
                     "ports": [{"name": "store", "protocol": "TCP",
                                "port": PORT, "targetPort": PORT}]}}


def _get_pod(lab, name):
    return json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)


def _wait_running(lab, name, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _get_pod(lab, name)
        status = last.get("status", {})
        if status.get("phase") == "Running":
            containers = status.get("containerStatuses", [])
            if len(containers) == 1 and containers[0].get("ready") is True:
                return last
            if len(containers) == 1 and containers[0].get("state", {}).get("running"):
                return last
        # Rank one can finish before the following poll observes Running;
        # Succeeded still proves that the owned Pod started normally.
        if status.get("phase") == "Succeeded":
            return last
        if status.get("phase") == "Failed":
            break
        time.sleep(0.25)
    lab.block(f"The owned collective Pod {name} did not start within its bound")
    return last


def _wait_rank_zero_endpoint(lab, pod_ip, timeout=30):
    deadline = time.monotonic() + timeout
    latest = {"items": []}
    while time.monotonic() < deadline:
        latest = json.loads(_kubectl(
            lab, "-n", NAMESPACE, "get", "endpointslices", "-l",
            f"kubernetes.io/service-name={RANK0_SERVICE}", "-o", "json").stdout)
        addresses = [address for item in latest.get("items", [])
                     for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready")
                     for address in endpoint.get("addresses", [])]
        if addresses == [pod_ip]:
            return latest, addresses
        time.sleep(0.25)
    return latest, []


def _worker_result(lab, name):
    pod = _get_pod(lab, name)
    if pod.get("status", {}).get("phase") != "Succeeded":
        lab.block(f"The owned collective Pod {name} did not complete successfully")
    result = _kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{name}", timeout=20).stdout.strip()
    try:
        rows = [json.loads(line.removeprefix("SAF_GLOO_RESULT "))
                for line in result.splitlines() if line.startswith("SAF_GLOO_RESULT ")]
    except json.JSONDecodeError:
        lab.block(f"The owned collective Pod {name} emitted no bounded result record")
    if len(rows) != 1:
        lab.block(f"The owned collective Pod {name} emitted an unexpected result count")
    return rows[0]


def _wait_succeeded(lab, names, timeout=90):
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        latest = {name: _get_pod(lab, name) for name in names}
        phases = {name: pod.get("status", {}).get("phase")
                  for name, pod in latest.items()}
        if all(phase == "Succeeded" for phase in phases.values()):
            return latest
        if any(phase == "Failed" for phase in phases.values()):
            break
        time.sleep(0.25)
    lab.block("The bounded two-rank collective did not complete successfully")
    return latest


def _cleanup(lab):
    for kind, names in (("pod", ("gloo-worker-a", "gloo-worker-b", "gloo-enrollment")),
                        ("service", (RANK0_SERVICE, ENROLLMENT_SERVICE)),
                        ("configmap", ("gloo-server-code", "gloo-worker-code"))):
        for name in names:
            _kubectl(lab, "-n", NAMESPACE, "delete", kind, name,
                     "--ignore-not-found=true", "--wait=true", allow_failure=True, timeout=35)


def run(lab, case_dir, image, provenance):
    """Run two authenticated workers through the existing assignment gate and Gloo SUM.

    `image` is the short-lived, locally built and imported runtime supplied by
    the parent runner. `provenance` is the wheel-lock summary; it contains only
    architecture and package hashes, never package bytes or credentials.
    """
    fixture = Path(case_dir) / "fixtures"
    aggregator = (fixture / "aggregator.py").read_text(encoding="utf-8")
    server = (fixture / "collective_aggregator.py").read_text(encoding="utf-8")
    worker = (fixture / "gloo_worker.py").read_text(encoding="utf-8")
    requests = (fixture / "requests.json").read_text(encoding="utf-8")
    request_map = json.loads(requests)

    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "gloo-server-code", "namespace": NAMESPACE},
                 "data": {"aggregator.py": aggregator,
                          "collective_aggregator.py": server}})
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "gloo-worker-code", "namespace": NAMESPACE},
                 "data": {"gloo_worker.py": worker, "requests.json": requests}})

    # Remove the earlier client Pods after all 17 original checks. The same two
    # service accounts now identify exactly one live worker Pod apiece.
    for name in ("worker-a", "worker-b", "observer"):
        _kubectl(lab, "-n", NAMESPACE, "delete", "pod", name,
                 "--wait=true", timeout=35)

    # This separate mock reuses the exact published TokenReview and contribution
    # handler. Its only addition is a rank assignment returned after that same
    # TokenReview has authenticated an already-enrolled worker.
    _apply(lab, {"apiVersion": "v1", "kind": "Service",
                 "metadata": {"name": ENROLLMENT_SERVICE, "namespace": NAMESPACE},
                 "spec": {"type": "ClusterIP", "selector": {ROLE_LABEL: "enrollment"},
                          "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    _apply(lab, {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "gloo-enrollment", "namespace": NAMESPACE,
                              "labels": {ROLE_LABEL: "enrollment"}},
                 "spec": {"restartPolicy": "Always", "serviceAccountName": "aggregation",
                          "automountServiceAccountToken": True,
                          "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                              "seccompProfile": {"type": "RuntimeDefault"}},
                          "containers": [{"name": "server", "image":
                                          "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                                          "imagePullPolicy": "IfNotPresent",
                                          "command": ["python3", "/case/collective_aggregator.py"],
                                          "env": [{"name": "ENFORCEMENT_MODE", "value": "enforce"}],
                                          "ports": [{"containerPort": 8080}],
                                          "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080},
                                                             "periodSeconds": 1, "timeoutSeconds": 2},
                                          "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                        "limits": {"cpu": "100m", "memory": "64Mi"}},
                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                              "readOnlyRootFilesystem": True,
                                                              "capabilities": {"drop": ["ALL"]}},
                                          "volumeMounts": [{"name": "code", "mountPath": "/case",
                                                            "readOnly": True}]}],
                          "volumes": [{"name": "code", "configMap": {"name": "gloo-server-code"}}]}})
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready",
             "pod/gloo-enrollment", "--timeout=60s", timeout=70)
    _apply(lab, _service(RANK0_SERVICE, {IDENTITY_LABEL: "worker-a"}))

    worker_names = ("gloo-worker-a", "gloo-worker-b")
    try:
        rank_zero = _pod("gloo-worker-a", "worker-a", image)
        _apply(lab, rank_zero)
        rank_zero_live = _wait_running(lab, "gloo-worker-a")
        rank_zero_slices, rank_zero_addresses = _wait_rank_zero_endpoint(
            lab, rank_zero_live.get("status", {}).get("podIP"))
        if rank_zero_addresses != [rank_zero_live.get("status", {}).get("podIP")]:
            lab.block("The rank-zero Service does not select exactly the owned rank-zero Pod")

        rank_one = _pod("gloo-worker-b", "worker-b", image)
        _apply(lab, rank_one)
        rank_one_live = _wait_running(lab, "gloo-worker-b")
        succeeded_pods = _wait_succeeded(lab, worker_names)

        results = {name: _worker_result(lab, pod_name)
                   for name, pod_name in (("worker-a", "gloo-worker-a"),
                                          ("worker-b", "gloo-worker-b"))}
        server_log = _kubectl(lab, "-n", NAMESPACE, "logs", "pod/gloo-enrollment").stdout
        server_events = [json.loads(line) for line in server_log.splitlines() if line.strip()]
        pod_by_worker = {"worker-a": succeeded_pods["gloo-worker-a"],
                         "worker-b": succeeded_pods["gloo-worker-b"]}
        pod_objects = {name: {
            "name": pod.get("metadata", {}).get("name"),
            "uid": pod.get("metadata", {}).get("uid"),
            "service_account": pod.get("spec", {}).get("serviceAccountName"),
            "phase": pod.get("status", {}).get("phase"),
            "pod_ip": pod.get("status", {}).get("podIP"),
            "image": pod.get("spec", {}).get("containers", [{}])[0].get("image"),
            "image_id": pod.get("status", {}).get("containerStatuses", [{}])[0].get("imageID"),
            "node_name": pod.get("spec", {}).get("nodeName"),
            "role_label": pod.get("metadata", {}).get("labels", {}).get(ROLE_LABEL),
            "identity_label": pod.get("metadata", {}).get("labels", {}).get(IDENTITY_LABEL),
        } for name, pod in pod_by_worker.items()}
        exact_images = all(pod_objects[name].get("image") == image for name in RANKS)
        exact_results = all(
            results[name] == {"worker_id": name, "rank": RANKS[name],
                              "round_id": "round-7", "accepted_http_status": 200,
                              "accepted_response": {"status": "accepted"},
                              "torch_version": "2.15.0+cpu", "gloo_available": True,
                              "backend": "gloo", "device": "cpu", "world_size": 2,
                              "input": EXPECTED_INPUTS[name], "operation": "sum",
                              "result": EXPECTED}
            for name in RANKS)
        expected_events = [
            {"outcome": "accepted", "worker_id": "worker-a",
             "request": request_map["worker_a_valid"]},
            {"outcome": "accepted", "worker_id": "worker-b",
             "request": request_map["worker_b_valid"]},
            {"outcome": "enrolled_for_collective", "worker_id": "worker-a",
             "round_id": "round-7", "rank": 0},
            {"outcome": "enrolled_for_collective", "worker_id": "worker-b",
             "round_id": "round-7", "rank": 1},
        ]
        events_observed = sorted(expected_events,
                                 key=lambda row: (row["outcome"], row["worker_id"]))
        projected_events = []
        for row in server_events:
            if row.get("outcome") == "enrolled_for_collective":
                projected_events.append({key: row.get(key)
                                         for key in ("outcome", "worker_id", "round_id", "rank")})
            elif row.get("outcome") == {"status": "accepted"}:
                projected_events.append({"outcome": "accepted",
                                         "worker_id": row.get("authenticated_identity"),
                                         "request": row.get("request")})
        actual_events = sorted(projected_events,
                               key=lambda row: (row["outcome"], row["worker_id"]))
        enrollment_ok = len(server_events) == len(expected_events) and actual_events == events_observed
        raw = {"scope": "Two legitimate synthetic worker Pods each submit their existing fixed in-range vector to the reused TokenReview/schema/assignment handler, receive a rank only after authenticated enrollment, and perform one real CPU Gloo SUM all-reduce. No model training, hostile input, or external target.",
               "runtime_image": image, "runtime_provenance": provenance,
               "expected_torch_version": "2.15.0+cpu", "expected_backend": "gloo",
               "request_keys": REQUEST_KEYS, "expected_rank_mapping": RANKS,
               "expected_inputs": EXPECTED_INPUTS, "expected_sum": EXPECTED,
               "actual_worker_results": results, "server_events": server_events,
               "expected_projected_events": events_observed,
               "observed_projected_events": actual_events, "pods": pod_objects,
               "rank_zero_endpoint_slices": rank_zero_slices,
               "rank_zero_endpoint_addresses": rank_zero_addresses,
               "enrollment_assignments_match": enrollment_ok,
               "worker_outputs_match": exact_results,
               "runtime_image_matches": exact_images,
               "tokens_or_credentials_logged": False,
               "external_targets_accessed": False,
               "model_training_performed": False}
        _raw(lab.evidence / "gloo-two-rank-raw.json", raw)
        lab.check("positive",
                  "Two distinct TokenReview-authenticated enrolled worker Pods receive their fixed ranks and run the pinned CPU Gloo runtime",
                  enrollment_ok and exact_images and all(pod_objects[name].get("phase") == "Succeeded"
                                                           for name in RANKS),
                  {"distinct_enrolled_identities_and_ranks": enrollment_ok,
                   "pinned_runtime_image_on_both_workers": exact_images,
                   "both_owned_rank_pods_completed": all(
                       pod_objects[name].get("phase") == "Succeeded" for name in RANKS),
                   "raw_evidence": "gloo-two-rank-raw.json"})
        lab.check("positive",
                  "The two-rank CPU Gloo all-reduce returns the exact fixed-vector sum to both enrolled workers",
                  exact_results,
                  {"both_worker_results_equal_expected_sum": exact_results,
                   "backend": "gloo", "device": "cpu", "world_size": 2,
                   "vector_length": 3, "collectives_per_worker": 1,
                   "expected_sum": EXPECTED,
                   "raw_evidence": "gloo-two-rank-raw.json"})
    finally:
        _cleanup(lab)
