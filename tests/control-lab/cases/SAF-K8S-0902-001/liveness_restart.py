"""Scratch-only supplement: observe kubelet liveness restart and recovery."""
import json
from pathlib import Path
import time


CONTROL_ID = "SAF-K8S-0902-001"
NAMESPACE = "saf-0902-001-live"
POD = "mock-inference-liveness"
CONTAINER = "mock-inference"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
MARKER = "/case-work/finite-unhealthy.marker"

SERVER = r'''
import http.server
from pathlib import Path

marker = Path("/case-work/finite-unhealthy.marker")
# A fresh container starts healthy; the bounded emptyDir is Pod-scoped.
marker.unlink(missing_ok=True)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ready":
            status, body = 200, b"ready"
        elif self.path == "/live":
            unhealthy = marker.exists()
            status, body = (503, b"temporarily-unhealthy") if unhealthy else (200, b"live")
        else:
            status, body = 404, b"not-found"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def resource():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD, "namespace": NAMESPACE,
                     "labels": {"app": POD, "saf-lab.example/control": CONTROL_ID,
                                "saf-lab.example/fixture": "synthetic"}},
        "spec": {
            "restartPolicy": "Always",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {
                "runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": CONTAINER, "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-c", SERVER],
                "ports": [{"name": "http", "containerPort": 8080}],
                "readinessProbe": {
                    "httpGet": {"path": "/ready", "port": "http"},
                    "periodSeconds": 2, "timeoutSeconds": 1,
                    "failureThreshold": 2,
                },
                "livenessProbe": {
                    "httpGet": {"path": "/live", "port": "http"},
                    "periodSeconds": 2, "timeoutSeconds": 1,
                    "failureThreshold": 2,
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "case-work", "mountPath": "/case-work"}],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
            }],
            "volumes": [{"name": "case-work", "emptyDir": {"sizeLimit": "1Mi"}}],
        },
    }


def get_pod(lab):
    raw = lab.kubectl("-n", NAMESPACE, "get", "pod", POD, "-o", "json").stdout
    return json.loads(raw)


def container_status(pod):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    return next((status for status in statuses if status.get("name") == CONTAINER), {})


def ready(pod):
    return any(condition.get("type") == "Ready" and condition.get("status") == "True"
               for condition in pod.get("status", {}).get("conditions", []))


def liveness_events(lab, uid):
    raw = lab.kubectl(
        "-n", NAMESPACE, "get", "events",
        "--field-selector", f"involvedObject.uid={uid}", "-o", "json",
    ).stdout
    document = json.loads(raw)
    return [event for event in document.get("items", [])
            if event.get("reason") == "Unhealthy"
            and "Liveness probe failed" in event.get("message", "")]


def run_liveness(lab):
    namespace = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": NAMESPACE,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "pod-security.kubernetes.io/enforce": "restricted",
                                "pod-security.kubernetes.io/enforce-version": "v1.36"}},
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(namespace))
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(resource()))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{POD}",
                "--timeout=120s", timeout=130)

    before = get_pod(lab)
    before_status = container_status(before)
    uid = before.get("metadata", {}).get("uid")
    initial_container_id = before_status.get("containerID")
    initial_restarts = before_status.get("restartCount", 0)
    spec = before.get("spec", {}).get("containers", [{}])[0]
    expected_liveness = {
        "httpGet": {"path": "/live", "port": "http", "scheme": "HTTP"},
        "periodSeconds": 2, "timeoutSeconds": 1, "failureThreshold": 2,
        "successThreshold": 1,
    }
    matches = spec.get("livenessProbe") == expected_liveness
    lab.check("green", "The restricted Pod runs the reviewed liveness probe and starts Ready",
              bool(uid) and bool(initial_container_id) and initial_restarts == 0
              and before.get("status", {}).get("phase") == "Running"
              and ready(before) and before_status.get("ready") is True
              and spec.get("image") == PYTHON_IMAGE and matches
              and before.get("spec", {}).get("securityContext", {}).get("runAsUser") == 10001
              and spec.get("securityContext", {}).get("readOnlyRootFilesystem") is True,
              {"pod_uid_present": bool(uid), "initial_ready": ready(before),
               "initial_restart_count": initial_restarts, "liveness_probe_matches": matches})

    # Trigger the fixed unhealthy state and witness it in a single bounded container exec.
    observe_unhealthy = f"""
import urllib.error
import urllib.request
from pathlib import Path
marker = Path({MARKER!r})
marker.write_text("finite-fixture-state")
assert marker.read_text() == "finite-fixture-state"
try:
    urllib.request.urlopen("http://127.0.0.1:8080/live", timeout=2)
except urllib.error.HTTPError as error:
    print(error.code)
"""
    failed_status = lab.kubectl("-n", NAMESPACE, "exec", POD, "-c", CONTAINER, "--",
                                "python", "-B", "-c", observe_unhealthy, timeout=13).stdout.strip()
    lab.check("red", "Changing only the fixed scratch marker produces an HTTP 503 on liveness",
              failed_status == "503", {"live_route_status_before_restart": failed_status})

    deadline = time.monotonic() + 100
    after = {}
    unhealthy = []
    while time.monotonic() < deadline:
        after = get_pod(lab)
        status = container_status(after)
        unhealthy = liveness_events(lab, uid)
        if (after.get("metadata", {}).get("uid") == uid
                and status.get("restartCount", 0) == initial_restarts + 1
                and status.get("containerID") != initial_container_id
                and status.get("ready") is True and ready(after) and unhealthy):
            break
        time.sleep(1)
    else:
        lab.block("Kubelet did not restart and recover the same fixture Pod within 100 seconds")

    final_status = container_status(after)
    last = final_status.get("lastState", {}).get("terminated", {})
    recovered_live = lab.kubectl(
        "-n", NAMESPACE, "exec", POD, "-c", CONTAINER, "--", "python", "-c",
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/live', timeout=2).status)",
        timeout=10,
    ).stdout.strip().splitlines()[-1]
    marker_absent = lab.kubectl(
        "-n", NAMESPACE, "exec", POD, "-c", CONTAINER, "--", "python", "-c",
        f"from pathlib import Path; print(not Path({MARKER!r}).exists())", timeout=10,
    ).stdout.strip().splitlines()[-1]
    (lab.evidence / "liveness-restart.raw.json").write_text(json.dumps({
        "pod_uid_before": uid,
        "pod_uid_after": after.get("metadata", {}).get("uid"),
        "container_id_before": initial_container_id,
        "container_id_after": final_status.get("containerID"),
        "failure_event_messages": [event.get("message") for event in unhealthy],
        "previous_exit_code": last.get("exitCode"),
    }, indent=2) + "\n")
    lab.check("positive", "Kubelet restarts and recovers the same Pod after the local liveness failure",
              after.get("metadata", {}).get("uid") == uid
              and final_status.get("restartCount", 0) == initial_restarts + 1
              and final_status.get("containerID") != initial_container_id
              and final_status.get("ready") is True and ready(after)
              and last.get("exitCode") is not None
              and bool(unhealthy) and recovered_live == "200" and marker_absent == "True",
              {"same_pod_uid": after.get("metadata", {}).get("uid") == uid,
               "restart_count_before": initial_restarts,
               "restart_count_after": final_status.get("restartCount"),
               "container_id_changed": final_status.get("containerID") != initial_container_id,
               "container_ready_after_restart": final_status.get("ready"),
               "pod_ready_after_restart": ready(after),
               "kubelet_liveness_failure_event": bool(unhealthy),
               "last_exit_code_present": last.get("exitCode") is not None,
               "live_route_status_after_restart": recovered_live,
               "finite_marker_cleared": marker_absent == "True"})
