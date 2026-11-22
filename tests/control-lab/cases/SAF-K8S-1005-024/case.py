"""Exercise bounded containment mechanics with synthetic workloads only."""
import base64
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
MOCK_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = FIXTURES["namespace"]
CASE_LABEL = "saf-k8s.example/case"
ROLE_LABEL = "saf-k8s.example/role"
INFERENCE = FIXTURES["inference"]
HEALTHY = FIXTURES["healthy_comparator"]
TRAINING = FIXTURES["training"]
CHECKPOINT = FIXTURES["checkpoint"]

SCOPE = (
    "One disposable Kind v1.36.1 cluster and one case-owned namespace. Digest-pinned Python "
    "mock HTTP Deployments represent inference and an independent healthy fixture; a native "
    "Kubernetes Job runs only a sleep loop and is then suspended. The case observes request "
    "availability, the target Deployment and EndpointSlice state, Job suspension and Pod "
    "removal, exact readback of immutable inert checkpoint bytes, and continued availability "
    "of the independent fixture. It does not validate organizational playbooks, real model or "
    "pipeline behavior, application-level checkpoint consistency, Argo or other orchestrators, "
    "production state safety, customer impact, or the control's full AI-specific response claim."
)

SERVER = r'''import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"fixture": os.environ["FIXTURE_MARKER"], "synthetic": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def _security():
    return {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _labels(role):
    return {CASE_LABEL: "1005-024", ROLE_LABEL: role}


def _serving_resources(name, role, marker):
    labels = {"app": name, **_labels(role)}
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": _labels(role),
                     "annotations": {"saf-k8s.example/incident": FIXTURES["incident_id"]}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 3,
                    "containers": [{
                        "name": "mock-http",
                        "image": MOCK_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", SERVER],
                        "env": [{"name": "FIXTURE_MARKER", "value": marker}],
                        "ports": [{"name": "http", "containerPort": 8080}],
                        "readinessProbe": {"httpGet": {"path": "/", "port": "http"},
                                           "periodSeconds": 2},
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "96Mi"}},
                        "securityContext": _security(),
                    }],
                },
            },
        },
    }
    if role == "healthy":
        _mount_checkpoint(deployment["spec"]["template"]["spec"])
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels(role)},
        "spec": {"type": "ClusterIP", "selector": {"app": name},
                 "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]},
    }
    return deployment, service


def _checkpoint_object():
    raw = CHECKPOINT["bytes_ascii"].encode("ascii")
    return raw, {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": CHECKPOINT["configmap"], "namespace": NAMESPACE,
                     "labels": _labels("checkpoint"),
                     "annotations": {"saf-k8s.example/incident": FIXTURES["incident_id"]}},
        "binaryData": {"checkpoint.bin": base64.b64encode(raw).decode("ascii")},
    }


def _mount_checkpoint(pod_spec):
    pod_spec["volumes"] = [{"name": "checkpoint", "configMap": {"name": CHECKPOINT["configmap"]}}]
    pod_spec["containers"][0]["volumeMounts"] = [
        {"name": "checkpoint", "mountPath": "/fixture-checkpoint", "readOnly": True}
    ]


def _training_job():
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": TRAINING["job"], "namespace": NAMESPACE,
                     "labels": _labels("training"),
                     "annotations": {"saf-k8s.example/incident": FIXTURES["incident_id"]}},
        "spec": {
            "backoffLimit": 0,
            "suspend": False,
            "template": {
                "metadata": {"labels": _labels("training")},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 3,
                    "containers": [{
                        "name": "inert-worker",
                        "image": MOCK_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "96Mi"}},
                        "securityContext": _security(),
                    }],
                },
            },
        },
    }

    _mount_checkpoint(job["spec"]["template"]["spec"])
    return job


def _get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _pods(lab, role):
    result = _get_json(lab, "get", "pods", "-l", f"{CASE_LABEL}=1005-024,{ROLE_LABEL}={role}")
    return result["items"]


def _request(lab, service, marker):
    code = (
        "import json,urllib.request; "
        f"x=json.load(urllib.request.urlopen('http://{service}:8080/',timeout=4)); "
        "print(json.dumps(x,sort_keys=True))"
    )
    result = lab.kubectl("exec", f"deployment/{HEALTHY['deployment']}", "--",
                         "python", "-c", code, allow_failure=True, timeout=15)
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        value = {}
    return result.returncode == 0 and value == {"fixture": marker, "synthetic": True}, {
        "reachable": result.returncode == 0 and value == {"fixture": marker, "synthetic": True},
        "exit_code": result.returncode,
        "response": value,
    }


def _endpoint_slices(lab, service):
    return _get_json(lab, "get", "endpointslices", "-l", f"kubernetes.io/service-name={service}")


def _ready_addresses(endpoint_slices):
    return [address for item in endpoint_slices["items"]
            for endpoint in (item.get("endpoints") or ())
            if endpoint.get("conditions", {}).get("ready") is True
            for address in endpoint.get("addresses", [])]


def _mounted_checkpoint_digest(lab, resource):
    script = ("from hashlib import sha256; from pathlib import Path; "
              "print(sha256(Path('/fixture-checkpoint/checkpoint.bin').read_bytes()).hexdigest())")
    return lab.kubectl("exec", resource, "--", "python", "-c", script).stdout.strip()


def _checkpoint_matches(obj, expected):
    try:
        actual = base64.b64decode(obj["binaryData"]["checkpoint.bin"], validate=True)
    except (KeyError, ValueError):
        return False, b""
    return obj.get("immutable") is True and actual == expected, actual


def _wait(lab, predicate, description, timeout=75):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (KeyError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    lab.block(f"Timed out waiting for {description}")


def _write_raw_evidence(lab, snapshot):
    (lab.evidence / "containment-observations.raw.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(lab):
    # The framework creates saf-test in its fresh cluster. Stay inside it.
    namespace = _get_json(lab, "get", "namespace", NAMESPACE)
    lab.check("positive", "The fixture uses only the runner-owned disposable namespace",
              namespace["metadata"]["name"] == NAMESPACE,
              {"namespace": namespace["metadata"]["name"]})

    checkpoint_bytes, checkpoint = _checkpoint_object()
    lab.create(checkpoint)
    inference_dep, inference_svc = _serving_resources(
        INFERENCE["deployment"], "inference", INFERENCE["route_marker"])
    healthy_dep, healthy_svc = _serving_resources(
        HEALTHY["deployment"], "healthy", HEALTHY["route_marker"])
    lab.create(inference_dep)
    lab.create(inference_svc)
    lab.create(healthy_dep)
    lab.create(healthy_svc)
    lab.kubectl("rollout", "status", f"deployment/{INFERENCE['deployment']}", "--timeout=90s", timeout=100)
    lab.kubectl("rollout", "status", f"deployment/{HEALTHY['deployment']}", "--timeout=90s", timeout=100)

    job = _training_job()
    lab.create(job)
    selector = f"{CASE_LABEL}=1005-024,{ROLE_LABEL}=training"
    lab.kubectl("wait", "--for=create", "pod", "-l", selector, "--timeout=20s", timeout=30)
    lab.kubectl("wait", "--for=condition=Ready", "pod", "-l", selector,
                "--timeout=75s", timeout=85)
    training_pods = _pods(lab, "training")
    if len(training_pods) != 1:
        lab.block("Expected one ready fixture training Pod")
    training_pod = training_pods[0]["metadata"]["name"]
    before_mount_hash = _mounted_checkpoint_digest(lab, f"pod/{training_pod}")
    expected_hash = hashlib.sha256(checkpoint_bytes).hexdigest()

    inference_reachable, before_route = _request(
        lab, INFERENCE["service"], INFERENCE["route_marker"])
    deployment_before = _get_json(lab, "get", "deployment", INFERENCE["deployment"])
    endpoints_before = _endpoint_slices(lab, INFERENCE["service"])
    inference_pods_before = _pods(lab, "inference")
    training_pods_before = _pods(lab, "training")
    healthy_pods_before = _pods(lab, "healthy")
    healthy_before, healthy_route_before = _request(lab, HEALTHY["service"], HEALTHY["route_marker"])
    before_checkpoint = _get_json(lab, "get", "configmap", CHECKPOINT["configmap"])
    checkpoint_before_ok, checkpoint_before_bytes = _checkpoint_matches(before_checkpoint, checkpoint_bytes)
    before_job = _get_json(lab, "get", "job", TRAINING["job"])
    lab.check("red", "Before containment, the mock inference route is available and the native Job is active",
              inference_reachable and before_job["spec"].get("suspend") is False
              and before_job.get("status", {}).get("active", 0) == 1 and bool(_pods(lab, "training")),
              {"inference_route": before_route, "job_suspend": before_job["spec"].get("suspend"),
               "active_pods": len(_pods(lab, "training"))})
    lab.check("positive", "The pre-containment checkpoint fixture has the expected inert bytes",
              checkpoint_before_ok and checkpoint_before_bytes == checkpoint_bytes
              and before_mount_hash == expected_hash,
              {"mounted_sha256": before_mount_hash, "sha256": hashlib.sha256(checkpoint_before_bytes).hexdigest(),
               "byte_count": len(checkpoint_before_bytes), "immutable": before_checkpoint.get("immutable")})

    lab.kubectl("scale", f"deployment/{INFERENCE['deployment']}", "--replicas=0")
    lab.kubectl("patch", "job", TRAINING["job"], "--type=merge", "-p", '{"spec":{"suspend":true}}')

    def target_contained():
        deployment = _get_json(lab, "get", "deployment", INFERENCE["deployment"])
        endpoints = _endpoint_slices(lab, INFERENCE["service"])
        pods = _pods(lab, "inference")
        return (deployment.get("status", {}).get("observedGeneration")
                == deployment["metadata"]["generation"]
                and deployment["spec"].get("replicas") == 0
                and deployment.get("status", {}).get("availableReplicas", 0) == 0
                and not _ready_addresses(endpoints) and not pods)

    _wait(lab, target_contained, "mock inference Deployment and Service endpoints to reach zero")

    def job_suspended():
        value = _get_json(lab, "get", "job", TRAINING["job"])
        conditions = value.get("status", {}).get("conditions", [])
        suspended_condition = any(c.get("type") == "Suspended" and c.get("status") == "True"
                                  for c in conditions)
        if value.get("spec", {}).get("suspend") is True and suspended_condition and not _pods(lab, "training"):
            return value, suspended_condition
        return None

    job_state, suspended_condition = _wait(
        lab, job_suspended, "native Job suspension and active Pod removal")
    job_api = _get_json(lab, "get", "job", TRAINING["job"])
    condition_observed = any(c.get("type") == "Suspended" and c.get("status") == "True"
                             for c in job_api.get("status", {}).get("conditions", []))
    target_reachable, target_after_route = _request(
        lab, INFERENCE["service"], INFERENCE["route_marker"])
    endpoint_after = _endpoint_slices(lab, INFERENCE["service"])
    deployment_after = _get_json(lab, "get", "deployment", INFERENCE["deployment"])
    inference_pods_after = _pods(lab, "inference")
    training_pods_after = _pods(lab, "training")
    green = (deployment_after["spec"].get("replicas") == 0
             and deployment_after.get("status", {}).get("availableReplicas", 0) == 0
             and not _ready_addresses(endpoint_after) and not inference_pods_after
             and job_api["spec"].get("suspend") is True and condition_observed
             and not training_pods_after and not target_reachable)
    lab.check("green", "Containment removes mock inference endpoints and suspends the native Job",
              green,
              {"deployment_replicas": deployment_after["spec"].get("replicas"),
               "available_replicas": deployment_after.get("status", {}).get("availableReplicas", 0),
               "ready_endpoints": _ready_addresses(endpoint_after),
               "inference_pods": len(inference_pods_after),
               "job_suspend": job_api["spec"].get("suspend"),
               "job_suspended_condition": condition_observed,
               "training_pods": len(training_pods_after),
               "inference_route": target_after_route})

    checkpoint_after = _get_json(lab, "get", "configmap", CHECKPOINT["configmap"])
    checkpoint_after_ok, checkpoint_after_bytes = _checkpoint_matches(checkpoint_after, checkpoint_bytes)
    after_mount_hash = _mounted_checkpoint_digest(lab, f"deployment/{HEALTHY['deployment']}")
    checkpoint_equal = (checkpoint_after_ok and checkpoint_after_bytes == checkpoint_before_bytes
                        and checkpoint_after["metadata"]["uid"] == before_checkpoint["metadata"]["uid"]
                        and before_mount_hash == after_mount_hash == expected_hash)
    lab.check("green", "Immutable inert checkpoint bytes remain identical after containment",
              checkpoint_equal,
              {"mounted_sha256_after": after_mount_hash, "sha256_before": hashlib.sha256(checkpoint_before_bytes).hexdigest(),
               "sha256_after": hashlib.sha256(checkpoint_after_bytes).hexdigest(),
               "byte_count": len(checkpoint_after_bytes), "immutable": checkpoint_after.get("immutable")})

    healthy_reachable, healthy_route = _request(lab, HEALTHY["service"], HEALTHY["route_marker"])
    healthy_endpoints = _endpoint_slices(lab, HEALTHY["service"])
    healthy_deployment_after = _get_json(lab, "get", "deployment", HEALTHY["deployment"])
    healthy_pods_after = _pods(lab, "healthy")
    same_healthy_pod = (len(healthy_pods_before) == len(healthy_pods_after) == 1
                        and healthy_pods_before[0]["metadata"]["uid"] == healthy_pods_after[0]["metadata"]["uid"]
                        and healthy_pods_after[0]["status"]["containerStatuses"][0]["restartCount"] == 0)
    unaffected = (healthy_before and healthy_reachable and bool(_ready_addresses(healthy_endpoints))
                  and same_healthy_pod
                  and healthy_deployment_after.get("status", {}).get("availableReplicas") == 1)
    lab.check("positive", "Independent healthy fixture remains reachable after target containment",
              unaffected,
              {"healthy_route_before": healthy_route_before, "healthy_route_after": healthy_route,
               "same_healthy_pod": same_healthy_pod,
               "ready_endpoint_count": len(_ready_addresses(healthy_endpoints)),
               "healthy_pods": len(healthy_pods_after),
               "available_replicas": healthy_deployment_after.get("status", {}).get("availableReplicas")})

    _write_raw_evidence(lab, {
        "case_id": FIXTURES["case_id"],
        "scope": "synthetic disposable-cluster observations; no Secret objects or credential data",
        "incident_metadata": FIXTURES["incident_metadata"],
        "inference_deployment_before": deployment_before,
        "inference_endpoints_before": endpoints_before,
        "inference_pods_before": inference_pods_before,
        "training_pods_before": training_pods_before,
        "healthy_pods_before": healthy_pods_before,
        "inference_deployment_after": deployment_after,
        "inference_endpoints_after": endpoint_after,
        "inference_pods_after": inference_pods_after,
        "training_pods_after": training_pods_after,
        "inference_probe_before": before_route,
        "inference_probe_after": target_after_route,
        "healthy_deployment_after": healthy_deployment_after,
        "healthy_pods_after": healthy_pods_after,
        "healthy_probe_before": healthy_route_before,
        "healthy_probe_after": healthy_route,
        "healthy_endpoints_after": healthy_endpoints,
        "job_before": before_job,
        "job_after": job_api,
        "checkpoint_before": before_checkpoint,
        "checkpoint_after": checkpoint_after,
        "checkpoint_sha256": hashlib.sha256(checkpoint_after_bytes).hexdigest(),
        "checkpoint_bytes_equal": checkpoint_equal,
        "mounted_sha256_before": before_mount_hash,
        "mounted_sha256_after": after_mount_hash,
        "job_suspended_state": job_state,
        "suspended_condition_returned": suspended_condition,
    })
