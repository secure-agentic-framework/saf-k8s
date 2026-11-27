"""Run finite real-monotonic deadline/cancellation checks against an owned HTTP worker."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
WORKER = "deadline-worker"
SERVICE = "deadline-worker"
CLIENT = "deadline-client"
PORT = 8080
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
WORKER_SHA256 = "104b1c49bcbf4f9d65139bc937d35db200ac147a9f61ed342e75219c5229c403"
CLIENT_SHA256 = "f6c31e0e4827646e34845f091e43534b2a21386a2172ac6fd0b00211e7a81201"


def _get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _pod_resource(name, labels, command):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": labels},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": name, "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": command,
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "runAsGroup": 65534,
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _ready_pod(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    pod = _get_json(lab, "get", "pod", name)
    statuses = {row.get("name"): row for row in
                pod.get("status", {}).get("containerStatuses", [])}
    if (not pod.get("metadata", {}).get("uid")
            or statuses.get(name, {}).get("ready") is not True
            or not statuses.get(name, {}).get("imageID")):
        lab.block(f"Owned deadline fixture Pod {name} did not become ready and identified")
    return pod


def _check_endpoint(lab, worker_pod):
    metadata = worker_pod["metadata"]
    worker_ip = worker_pod["status"].get("podIP")
    document = _get_json(lab, "get", "endpointslices.discovery.k8s.io", "-l",
                         f"kubernetes.io/service-name={SERVICE}")
    endpoints = []
    for item in document.get("items", []):
        for endpoint in item.get("endpoints", []):
            endpoints.append({
                "ready": endpoint.get("conditions", {}).get("ready"),
                "target": endpoint.get("targetRef", {}),
                "addresses": endpoint.get("addresses", []),
            })
    expected = {"kind": "Pod", "uid": metadata["uid"],
                "name": metadata["name"], "namespace": metadata["namespace"]}
    matches = (len(endpoints) == 1 and bool(worker_ip)
               and endpoints[0]["addresses"] == [worker_ip]
               and endpoints[0]["ready"] is True
               and all(endpoints[0]["target"].get(key) == value
                       for key, value in expected.items()))
    return matches, document


def _deadline_worker_resource():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": WORKER,
                     "labels": {"saf-lab.example/fixture": "real-deadline-worker"}},
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app": WORKER}},
            "template": {
                "metadata": {"labels": {"app": WORKER,
                                         "saf-lab.example/fixture": "real-deadline-worker"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "runAsGroup": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "source", "configMap": {
                        "name": WORKER + "-source", "defaultMode": 0o444}}],
                    "containers": [{
                        "name": "worker", "image": IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/fixture/deadline_worker.py"],
                        "ports": [{"name": "http", "containerPort": PORT}],
                        "volumeMounts": [{"name": "source", "mountPath": "/fixture",
                                          "readOnly": True}],
                        "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                                           "periodSeconds": 1, "timeoutSeconds": 1,
                                           "failureThreshold": 20},
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                            "runAsGroup": 65534,
                                            "allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                    }],
                },
            },
        },
    }


def run(lab):
    worker_code = (HERE / "deadline_worker.py").read_text(encoding="utf-8")
    client_code = (HERE / "deadline_client.py").read_text(encoding="utf-8")
    worker_sha = hashlib.sha256(worker_code.encode("utf-8")).hexdigest()
    client_sha = hashlib.sha256(client_code.encode("utf-8")).hexdigest()
    if worker_sha != WORKER_SHA256 or client_sha != CLIENT_SHA256:
        lab.block("The deadline worker/client sources differ from their reviewed SHA-256 pins")

    config = lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": WORKER + "-source"}, "immutable": True,
        "data": {"deadline_worker.py": worker_code},
    })
    if (config.get("immutable") is not True
            or config.get("data", {}).get("deadline_worker.py") != worker_code):
        lab.block("The immutable ConfigMap did not retain the exact pinned deadline worker")

    lab.create({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE},
        "spec": {"type": "ClusterIP", "selector": {"app": WORKER},
                 "ports": [{"name": "http", "port": PORT,
                            "targetPort": "http", "protocol": "TCP"}]},
    })
    lab.create(_deadline_worker_resource())
    lab.kubectl("rollout", "status", "deployment/" + WORKER,
                "--timeout=90s", timeout=100)
    pods = _get_json(lab, "get", "pods", "-l", "app=" + WORKER).get("items", [])
    active = [pod for pod in pods if not pod.get("metadata", {}).get("deletionTimestamp")]
    if len(active) != 1:
        lab.block("Expected exactly one active owned deadline worker Pod")
    worker_pod = active[0]
    worker_uid = worker_pod.get("metadata", {}).get("uid")
    worker_status = next((row for row in worker_pod.get("status", {}).get("containerStatuses", [])
                          if row.get("name") == "worker"), {})
    if (not worker_uid or worker_status.get("ready") is not True
            or not worker_status.get("imageID")):
        lab.block("The current deadline worker Pod is not ready and identity-bound")
    service_live = _get_json(lab, "get", "service", SERVICE)
    service_spec = service_live.get("spec", {})
    service_contract = (
        service_spec.get("type") == "ClusterIP"
        and bool(service_spec.get("clusterIP"))
        and service_spec.get("selector") == {"app": WORKER}
        and service_spec.get("ports") == [{"name": "http", "port": PORT,
                                            "protocol": "TCP", "targetPort": "http"}]
        and not service_spec.get("externalIPs")
    )
    if not service_contract:
        lab.block("The owned deadline Service must remain ClusterIP-only with its exact worker selector")
    endpoint_deadline = time.monotonic() + 15
    endpoints = None
    endpoint_matches = False
    while time.monotonic() < endpoint_deadline:
        endpoint_matches, endpoints = _check_endpoint(lab, worker_pod)
        if endpoint_matches:
            break
        time.sleep(0.25)
    if not endpoint_matches:
        lab.block("The ready deadline worker did not acquire its exact Service endpoint")

    client_resource = _pod_resource(
        CLIENT, {"saf-lab.example/fixture": "deadline-client"},
        ["python", "-B", "-c", "import time; time.sleep(240)"])
    lab.create(client_resource)
    client_pod = _ready_pod(lab, CLIENT)
    client_status = next((row for row in client_pod.get("status", {}).get("containerStatuses", [])
                          if row.get("name") == CLIENT), {})
    outcome = lab.kubectl("exec", "-i", "pod/" + CLIENT, "--",
                          "python", "-B", "-", payload=client_code,
                          timeout=20, allow_failure=True)
    try:
        report = json.loads(outcome.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Owned bounded deadline client returned invalid JSON: {error}")
    if outcome.returncode != 0:
        lab.block("The owned deadline client failed before returning its bounded observations")

    (lab.evidence / "inference-real-deadlines.raw.json").write_text(
        json.dumps({
            "scope": "owned inert HTTP worker; monotonic cooperative deadlines between fixed tiny work units",
            "worker": {"uid": worker_uid, "pod_name": worker_pod["metadata"]["name"],
                       "container_id": worker_status.get("containerID"),
                       "image_id": worker_status.get("imageID"),
                       "ready": worker_status.get("ready")},
            "client": {"uid": client_pod["metadata"]["uid"],
                       "container_id": client_status.get("containerID"),
                       "image_id": client_status.get("imageID")},
            "endpoint_slices": endpoints,
            "service": {"type": service_spec.get("type"),
                        "cluster_ip": service_spec.get("clusterIP"),
                        "selector": service_spec.get("selector"),
                        "ports": service_spec.get("ports")},
            "worker_source_sha256": worker_sha,
            "client_source_sha256": client_sha,
            "observations": report,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    request_timeout = report["request_expired"]
    request_result = request_timeout["body"]
    request_before = report["request_before"]["counters"]
    request_after = report["request_after_expired"]["counters"]
    request_allowed = report["request_allowed"]
    request_comp = request_allowed["body"]
    request_comp_before = request_after["work_units_completed"]
    request_comp_after = report["request_after_allowed"]["counters"]["work_units_completed"]
    request_ok = (
        request_timeout["status"] == 504 and request_result.get("deadline_stop") is True
        and request_result.get("deadline_ms") == 45
        and request_result.get("elapsed_ms", 0) >= 45
        and request_result.get("elapsed_ms", 0) < 5000
        and request_result.get("units_requested") == 8
        and 1 <= request_result.get("units_completed", 0) < 8
        and request_after["work_units_completed"] - request_before["work_units_completed"]
        == request_result.get("units_completed")
        and request_after["work_units_by_scope"]["request"]
        - request_before["work_units_by_scope"]["request"] == request_result.get("units_completed")
        and request_after["request_deadline_stops"] - request_before["request_deadline_stops"] == 1
        and request_after["accepted_requests"] == request_before["accepted_requests"]
        and request_allowed["status"] == 200 and request_comp.get("units_completed") == 2
        and not request_comp.get("deadline_stop")
        and request_comp_after - request_comp_before == 2
        and report["request_after_allowed"]["counters"]["work_units_by_scope"]["request"]
        - request_after["work_units_by_scope"]["request"] == 2
        and report["request_after_allowed"]["counters"]["accepted_requests"]
        - request_after["accepted_requests"] == 1
    )
    lab.check("green", "A measured request deadline stops bounded in-progress work and admits a within-budget comparator",
              request_ok,
              {"request_deadline_elapsed": request_result.get("elapsed_ms", 0) >= 45,
               "request_work_interrupted": 1 <= request_result.get("units_completed", 0) < 8,
               "request_worker_counter_matches_completed_units":
                   request_after["work_units_completed"] - request_before["work_units_completed"]
                   == request_result.get("units_completed"),
               "within_budget_request_completed": request_allowed["status"] == 200
                   and request_comp.get("units_completed") == 2})

    session_first = report["session_first"]
    session_expired = report["session_expired"]
    session_later = report["session_rejected_after_expiry"]
    session_before = report["session_before"]["counters"]
    after_first = report["session_after_first"]["counters"]
    after_expired = report["session_after_expired"]["counters"]
    after_later = report["session_after_rejected"]["counters"]
    session_allowed = report["session_allowed"]
    session_after_allowed = report["session_after_allowed"]["counters"]
    session_expired_body = session_expired["body"]
    session_later_body = session_later["body"]
    session_ok = (
        session_first["status"] == 200 and session_first["body"].get("units_completed") == 2
        and after_first["work_units_completed"] - session_before["work_units_completed"] == 2
        and after_first["work_units_by_scope"]["session"]
        - session_before["work_units_by_scope"]["session"] == 2
        and after_first["accepted_requests"] - session_before["accepted_requests"] == 1
        and session_expired["status"] == 504
        and session_expired_body.get("deadline_stop") is True
        and session_expired_body.get("scope_elapsed_ms", 0) >= 120
        and session_expired_body.get("scope_elapsed_ms", 0) < 5000
        and 1 <= session_expired_body.get("units_completed", 0) < 8
        and after_expired["work_units_completed"] - after_first["work_units_completed"]
        == session_expired_body.get("units_completed")
        and after_expired["work_units_by_scope"]["session"]
        - after_first["work_units_by_scope"]["session"] == session_expired_body.get("units_completed")
        and after_expired["session_deadline_stops"] - after_first["session_deadline_stops"] == 1
        and session_later["status"] == 504
        and session_later_body.get("units_completed") == 0
        and session_later_body.get("scope_elapsed_ms", 0) >= 120
        and after_later["work_units_completed"] == after_expired["work_units_completed"]
        and after_later["work_units_by_scope"]["session"]
        == after_expired["work_units_by_scope"]["session"]
        and after_later["session_deadline_stops"] - after_expired["session_deadline_stops"] == 1
        and session_allowed["status"] == 200
        and session_allowed["body"].get("units_completed") == 2
        and session_after_allowed["work_units_completed"] - after_later["work_units_completed"] == 2
        and session_after_allowed["work_units_by_scope"]["session"]
        - after_later["work_units_by_scope"]["session"] == 2
        and session_after_allowed["accepted_requests"] - after_later["accepted_requests"] == 1
    )
    lab.check("green", "A cumulative session deadline stops later work and rejects the expired session without more work",
              session_ok,
              {"first_session_request_completed": session_first["status"] == 200
                   and session_first["body"].get("units_completed") == 2,
               "later_session_work_interrupted": 1 <= session_expired_body.get("units_completed", 0) < 8,
               "expired_session_rejected_before_more_work": session_later["status"] == 504
                   and session_later_body.get("units_completed") == 0
                   and after_later["work_units_completed"] == after_expired["work_units_completed"],
               "separate_session_comparator_completed": session_allowed["status"] == 200
                   and session_allowed["body"].get("units_completed") == 2})

    batch_expired = report["batch_expired"]
    batch_before = report["batch_before"]["counters"]
    batch_after = report["batch_after_expired"]["counters"]
    batch_allowed = report["batch_allowed"]
    batch_after_allowed = report["batch_after_allowed"]["counters"]
    batch_body = batch_expired["body"]
    scope_totals = batch_after_allowed["work_units_by_scope"]
    global_accounting_exact = (
        batch_after_allowed["work_units_completed"] == sum(scope_totals.values())
        and batch_after_allowed["request_deadline_stops"] == 1
        and batch_after_allowed["session_deadline_stops"] == 2
        and batch_after_allowed["batch_deadline_stops"] == 1
        and batch_after_allowed["accepted_requests"] == 4
    )
    batch_ok = (
        batch_expired["status"] == 504 and batch_body.get("scope") == "batch"
        and batch_body.get("deadline_stop") is True
        and batch_body.get("deadline_ms") == 45
        and batch_body.get("elapsed_ms", 0) >= 45
        and batch_body.get("elapsed_ms", 0) < 5000
        and batch_body.get("units_requested") == 8
        and 1 <= batch_body.get("units_completed", 0) < 8
        and batch_after["work_units_completed"] - batch_before["work_units_completed"]
        == batch_body.get("units_completed")
        and batch_after["work_units_by_scope"]["batch"]
        - batch_before["work_units_by_scope"]["batch"] == batch_body.get("units_completed")
        and batch_after["batch_deadline_stops"] - batch_before["batch_deadline_stops"] == 1
        and batch_allowed["status"] == 200
        and batch_allowed["body"].get("units_completed") == 2
        and batch_after_allowed["work_units_completed"] - batch_after["work_units_completed"] == 2
        and batch_after_allowed["work_units_by_scope"]["batch"]
        - batch_after["work_units_by_scope"]["batch"] == 2
        and batch_after_allowed["accepted_requests"] - batch_after["accepted_requests"] == 1
        and global_accounting_exact
    )
    lab.check("green", "A measured batch deadline interrupts a bounded batch and admits an in-budget batch",
              batch_ok,
              {"batch_deadline_elapsed": batch_body.get("elapsed_ms", 0) >= 45,
               "batch_work_interrupted": 1 <= batch_body.get("units_completed", 0) < 8,
               "batch_worker_counter_matches_completed_units":
                   batch_after["work_units_completed"] - batch_before["work_units_completed"]
                   == batch_body.get("units_completed"),
               "within_budget_batch_completed": batch_allowed["status"] == 200
                   and batch_allowed["body"].get("units_completed") == 2,
               "worker_scope_counters_reconcile": global_accounting_exact})
