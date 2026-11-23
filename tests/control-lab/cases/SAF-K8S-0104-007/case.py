"""Exercise bounded emergency node maintenance and workload recovery checks."""

import json
import time

SCOPE = "Live cordon, PDB-protected drain, capacity addition, rescheduling, and worker restoration in an owned Kind cluster."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAME = "fixture-emergency-marker"
MARKER = "fixture public service healthy"
PROBE = "fixture-service-probe"
SERVER = """from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Marker(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'fixture public service healthy')
    def log_message(self, *_args):
        pass
ThreadingHTTPServer(('0.0.0.0', 8080), Marker).serve_forever()
"""


def prepare_kind(_lab, temporary):
    kind = temporary / "kind-emergency-maintenance.yaml"
    kind.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
""")
    return kind


def spec():
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c", SERVER],
            "readinessProbe": {"httpGet": {"path": "/", "port": 8080}, "periodSeconds": 1},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}}}
    return {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}],
            "containers": [unit]}


def objects(lab, kind, name=None, selector=None):
    arguments = ["get", kind]
    if name:
        arguments.append(name)
    if selector:
        arguments.extend(["--selector", selector])
    return json.loads(lab.kubectl(*arguments, "-o", "json").stdout)


def ready_pods(lab):
    return [pod for pod in objects(lab, "pods", selector=f"app={NAME}")["items"]
            if not pod["metadata"].get("deletionTimestamp") and any(
                condition["type"] == "Ready" and condition["status"] == "True"
                for condition in pod["status"].get("conditions", []))]


def wait_for(lab, predicate, message, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observation := predicate():
            return observation
        time.sleep(0.45)
    lab.block(message)


def drain(lab, worker, seconds):
    return lab.kubectl("drain", worker, "--ignore-daemonsets", f"--pod-selector=app={NAME}",
                       f"--timeout={seconds}s", timeout=seconds + 12, allow_failure=True)


def read_marker(lab, endpoint):
    script = "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=3).read().decode())"
    result = lab.kubectl("exec", "pod/" + PROBE, "--", "python", "-c", script,
                         f"http://{endpoint}:8080/", timeout=12, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == MARKER


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    worker = f"{lab.cluster}-worker"
    selector = {"app": NAME}
    probe = spec()
    probe["restartPolicy"] = "Never"
    probe["nodeSelector"] = {"node-role.kubernetes.io/control-plane": ""}
    unit, = probe["containers"]
    unit["command"] = ["python", "-c", "import time; time.sleep(240)"]
    del unit["readinessProbe"]
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": PROBE}, "spec": probe})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + PROBE, "--timeout=45s", timeout=55)
    control_plane = f"{lab.cluster}-control-plane"
    lab.kubectl("cordon", control_plane)
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": NAME}, "spec": {
        "replicas": 1, "selector": {"matchLabels": selector},
        "template": {"metadata": {"labels": selector}, "spec": spec()},
    }})
    lab.create({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": NAME},
                "spec": {"minAvailable": 1, "selector": {"matchLabels": selector}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": NAME}, "spec": {
        "selector": selector, "ports": [{"port": 8080, "targetPort": 8080}],
    }})
    first, = wait_for(lab, lambda: ready_pods(lab), "The initial marker was not ready")
    wait_for(lab, lambda: read_marker(lab, NAME), "The initial service did not serve the marker")
    if first["spec"]["nodeName"] != worker:
        lab.block("The marker was not placed on the selected worker")
    wait_for(lab, lambda: objects(lab, "pdb", NAME).get("status", {}).get("currentHealthy") == 1,
             "The disruption controller did not observe the initial ready marker")
    initial_uid = first["metadata"]["uid"]
    lab.kubectl("uncordon", control_plane)

    try:
        denied = drain(lab, worker, 8)
        still_ready = [pod for pod in ready_pods(lab) if pod["metadata"]["uid"] == initial_uid]
        blocked = denied.returncode != 0 and "disruption budget" in (denied.stdout + denied.stderr).lower()
        lab.check("red", "The guarded maintenance stops when the only Ready replica cannot be evicted",
                  blocked and len(still_ready) == 1 and read_marker(lab, NAME),
                  {"pdb_denied_eviction": blocked, "original_marker_still_ready": bool(still_ready)})

        lab.kubectl("scale", "deployment", NAME, "--replicas=2")
        wait_for(lab, lambda: objects(lab, "pdb", NAME).get("status", {}).get("disruptionsAllowed", 0) >= 1,
                 "Adding capacity did not establish an allowed disruption")
        approved = drain(lab, worker, 28)
        moved = wait_for(lab, lambda: (pods if len(pods := ready_pods(lab)) == 2
                                       and all(item["spec"]["nodeName"] != worker for item in pods) else []),
                         "The reviewed workload did not complete rescheduling")
        lab.check("green", "After adding capacity, the guarded drain succeeds and the public marker stays available",
                  approved.returncode == 0 and wait_for(lab, lambda: read_marker(lab, NAME), "Rescheduled Service did not answer"),
                  {"guarded_drain_succeeded": approved.returncode == 0, "replacement_markers_ready": len(moved)})
    finally:
        lab.kubectl("uncordon", worker)

    check = spec()
    check["restartPolicy"] = "Never"
    check["nodeSelector"] = {"kubernetes.io/hostname": worker}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "fixture-return-probe"}, "spec": check})
    lab.kubectl("wait", "--for=condition=Ready", "pod/fixture-return-probe", "--timeout=55s", timeout=65)
    returned = objects(lab, "pod", "fixture-return-probe")
    admitted = returned["spec"]["nodeName"] == worker and read_marker(lab, returned["status"]["podIP"])
    remaining = ready_pods(lab)
    maintained = len(remaining) == 2 and read_marker(lab, NAME)
    lab.check("positive", "The recovered worker accepts a fresh marker while the rescheduled service remains healthy",
              admitted and maintained, {"worker_return_verified": admitted, "rescheduled_service_verified": maintained})
    (lab.evidence / "emergency-maintenance-observations.json").write_text(json.dumps({
        "abort_on_pdb_denial": blocked, "capacity_added_before_drain": approved.returncode == 0,
        "worker_returned": admitted, "service_ready": maintained, "software_patch_installed": False,
    }, indent=2) + "\n")
