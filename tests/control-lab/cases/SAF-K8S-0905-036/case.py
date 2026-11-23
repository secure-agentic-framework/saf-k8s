"""Exercise metric-driven Deployment halt through a restricted live controller."""
import json
from pathlib import Path
import time

from fixtures import container


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
CONTROLLER = "threshold-controller"
TARGET = "threshold-target"
CONTROL = "threshold-control"
SERVICE = "threshold-control"
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster runs a namespace-scoped Python control loop "
    "against a case-owned numeric telemetry ConfigMap. The loop reads an explicit enabled flag "
    "and threshold, records a deterministic decision ConfigMap, and when enabled and value >= "
    "threshold patches only the target Deployment scale subresource to zero. The halt stays latched across restart. The test observes "
    "Deployment status and EndpointSlices and retains a separate available control Deployment. "
    "It proves this synthetic controller/API/RBAC path only; it does not establish production "
    "telemetry authenticity, policy governance, workload coverage, response-time objectives, "
    "serving-layer isolation, or training/pipeline Job behavior."
)


def _cm(name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data}


def _deployment(name, *, service_account="default", controller=False):
    labels = {"app": name}
    fixture_server = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b'NAME'
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_): pass
HTTPServer(('0.0.0.0',8080),Server).serve_forever()
""".replace("NAME", name)
    command = (["python", "-B", "/control/controller.py"] if controller else
               ["python", "-B", "-c", fixture_server])
    readiness = {} if controller else {"readinessProbe": {"tcpSocket": {"port": 8080}, "periodSeconds": 1}}

    spec = {"automountServiceAccountToken": controller, "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container(
                "controller" if controller else "http", image=PYTHON, command=command,
                ports=[] if controller else [{"name": "http", "containerPort": 8080}],
                resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                           "limits": {"cpu": "100m", "memory": "64Mi"}},
                securityContext={"allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "capabilities": {"drop": ["ALL"]}},
                volumeMounts=([{"name": "program", "mountPath": "/control", "readOnly": True}]
                              if controller else []), **readiness)],
            "volumes": ([{"name": "program", "configMap": {"name": "threshold-controller-code"}}]
                        if controller else [])}
    if controller:
        spec["serviceAccountName"] = service_account
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": labels}, "spec": spec}}}


def _decision(lab):
    raw = json.loads(lab.kubectl("get", "configmap/threshold-decision", "-o", "json").stdout)
    try:
        return json.loads(raw["data"]["decision.json"])
    except (KeyError, ValueError, TypeError):
        lab.block("Controller did not persist a parseable matched decision")


def _deployment_status(lab, name):
    raw = json.loads(lab.kubectl("get", f"deployment/{name}", "-o", "json").stdout)
    status = raw.get("status", {})
    return {"desired": raw["spec"].get("replicas", 0),
            "replicas": status.get("replicas", 0),
            "ready": status.get("readyReplicas", 0),
            "available": status.get("availableReplicas", 0)}


def _controller_pods(lab):
    response = lab.kubectl("get", "pods", "-l", f"app={CONTROLLER}", "-o", "json")
    return [pod["metadata"]["uid"] for pod in (json.loads(response.stdout).get("items") or [])]


def _ready_endpoint_count(lab, service):
    raw = json.loads(lab.kubectl("get", "endpointslices", "-l",
                                 f"kubernetes.io/service-name={service}", "-o", "json").stdout)
    return sum(1 for item in (raw.get("items") or []) for endpoint in (item.get("endpoints") or [])
               if endpoint.get("conditions", {}).get("ready") is True)


def _wait_for(lab, predicate, message, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.4)
    lab.block(message)


def _set(lab, name, data):
    lab.kubectl("patch", f"configmap/{name}", "--type=merge", "-p",
                json.dumps({"data": data}, sort_keys=True, separators=(",", ":")))


def run(lab):
    for name, data in (("threshold-telemetry", {"value": "95"}),
                       ("threshold-policy", {"enabled": "false", "threshold": "80"}),
                       ("threshold-decision", {"decision.json": "{}"})):
        lab.create(_cm(name, data))
    lab.create(_cm("threshold-controller-code", {
        "controller.py": (HERE / "controller.py").read_text(encoding="utf-8")}))

    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": CONTROLLER}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": CONTROLLER}, "rules": [
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": ["threshold-telemetry", "threshold-policy",
                                       "threshold-decision"], "verbs": ["get"]},
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": ["threshold-decision"], "verbs": ["patch"]},
                    {"apiGroups": ["apps"], "resources": ["deployments/scale"],
                     "resourceNames": [TARGET], "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": CONTROLLER},
                "subjects": [{"kind": "ServiceAccount", "name": CONTROLLER,
                              "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": CONTROLLER}})

    lab.create(_deployment(TARGET))
    lab.create(_deployment(CONTROL))
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": TARGET},
                "spec": {"selector": {"app": TARGET},
                         "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                "spec": {"selector": {"app": CONTROL},
                         "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    lab.create(_deployment(CONTROLLER, service_account=CONTROLLER, controller=True))
    for name in (TARGET, CONTROL, CONTROLLER):
        lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)

    _wait_for(lab, lambda: _decision(lab).get("reason") == "threshold_disabled"
              and _deployment_status(lab, TARGET)["available"] == 1
              and _ready_endpoint_count(lab, TARGET) == 1,
              "Disabled threshold decision did not reach the live controller")
    disabled = _decision(lab)
    target_live = _deployment_status(lab, TARGET)
    target_live_endpoints = _ready_endpoint_count(lab, TARGET)
    lab.check("red", "An over-threshold metric is observed but does not halt while policy is disabled",
              disabled == {"action": "continue", "enabled": False, "metric": 95,
                           "reason": "threshold_disabled", "target": TARGET, "threshold": 80}
              and target_live["available"] == 1 and target_live["desired"] == 1
              and target_live_endpoints == 1,
              {"decision": disabled, "target_status": target_live,
               "ready_endpoints": target_live_endpoints})

    _set(lab, "threshold-telemetry", {"value": "79"})
    _wait_for(lab, lambda: _decision(lab).get("metric") == 79,
              "The disabled controller did not observe the below-threshold sample")
    _set(lab, "threshold-policy", {"enabled": "true", "threshold": "80"})
    _wait_for(lab, lambda: _decision(lab).get("reason") == "below_threshold"
              and _deployment_status(lab, TARGET)["available"] == 1
              and _ready_endpoint_count(lab, TARGET) == 1,
              "Below-threshold decision did not reach the live controller")
    below = _decision(lab)
    below_status = _deployment_status(lab, TARGET)
    below_endpoints = _ready_endpoint_count(lab, TARGET)
    lab.check("green", "Enabled policy continues at a numeric value below threshold",
              below == {"action": "continue", "enabled": True, "metric": 79,
                        "reason": "below_threshold", "target": TARGET, "threshold": 80}
              and below_status["available"] == 1 and below_status["desired"] == 1
              and below_endpoints == 1,
              {"decision": below, "target_status": below_status,
               "ready_endpoints": below_endpoints})

    _set(lab, "threshold-telemetry", {"value": "80"})
    _wait_for(lab, lambda: _decision(lab).get("state") == "enforced",
              "Above-threshold decision did not reach the live controller")
    _wait_for(lab, lambda: _deployment_status(lab, TARGET)["replicas"] == 0
              and _ready_endpoint_count(lab, "threshold-target") == 0,
              "Deployment status or endpoints did not reach zero at the configured threshold")
    halted = _decision(lab)
    target_stopped = _deployment_status(lab, TARGET)
    target_endpoints = _ready_endpoint_count(lab, "threshold-target")
    lab.check("green", "At the inclusive threshold the controller scales down the target and removes ready endpoints",
              halted == {"action": "scale_to_zero", "enabled": True, "metric": 80,
                         "reason": "threshold_breached", "target": TARGET, "threshold": 80,
                         "last_observed_metric": 80, "state": "enforced"}
              and target_stopped["desired"] == 0 and target_stopped["replicas"] == 0
              and target_stopped["ready"] == 0 and target_stopped["available"] == 0
              and target_endpoints == 0,
              {"decision": halted, "target_status": target_stopped,
               "ready_endpoints": target_endpoints})

    old_pods = _controller_pods(lab)
    lab.kubectl("scale", f"deployment/{CONTROLLER}", "--replicas=0")
    _wait_for(lab, lambda: not _controller_pods(lab),
              "The original controller Pod is still present")
    _set(lab, "threshold-telemetry", {"value": "30"})
    lab.kubectl("scale", f"deployment/{CONTROLLER}", "--replicas=1")
    lab.kubectl("rollout", "status", f"deployment/{CONTROLLER}", "--timeout=75s", timeout=80)
    new_pods = _controller_pods(lab)
    replaced = len(old_pods) == len(new_pods) == 1 and old_pods != new_pods

    def observed_recovered_metric():
        if _decision(lab).get("last_observed_metric") == 30:
            return True
        lab.kubectl("logs", f"deployment/{CONTROLLER}", "--tail=20", allow_failure=True)
        return False

    _wait_for(lab, observed_recovered_metric, "Replacement controller never observed the recovered metric")
    latched = _decision(lab)
    current = _deployment_status(lab, TARGET)
    same_intent = latched == {**halted, "last_observed_metric": 30}
    lab.check("green", "The replacement controller preserves the original halt decision after the metric clears",
              replaced and same_intent and current == target_stopped and _ready_endpoint_count(lab, TARGET) == 0,
              {"controller_replaced": replaced, "trigger_preserved": same_intent,
               "target_still_halted": current == target_stopped})
    probe = container("probe", image=PYTHON, command=["sleep", "900"])
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "observer"},
                "spec": {"automountServiceAccountToken": False, "containers": [probe]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/observer", "--timeout=65s", timeout=70)
    response = lab.kubectl("exec", "pod/observer", "--", "python", "-B", "-c",
                           "import urllib.request; print(urllib.request.urlopen('http://threshold-control:8080',timeout=3).read().decode())")
    control_status = _deployment_status(lab, CONTROL)
    control_endpoints = _ready_endpoint_count(lab, SERVICE)
    lab.check("positive", "Unaffected control workload remains available through its Service",
              control_status["desired"] == 1 and control_status["available"] == 1
              and control_endpoints == 1 and response.stdout.strip() == CONTROL,
              {"control_status": control_status, "ready_endpoints": control_endpoints, "live_response": response.stdout.strip()})

    access = {}
    for verb, resource, name in (("get", "configmaps", "threshold-telemetry"),
                                  ("get", "configmaps", "threshold-policy"),
                                  ("get", "configmaps", "threshold-decision"),
                                  ("list", "configmaps", None),
                                  ("patch", "configmaps", "threshold-decision"),
                                  ("patch", "configmaps", "threshold-policy"),
                                  ("patch", "deployments/scale", TARGET),
                                  ("patch", "deployments/scale", CONTROL),
                                  ("patch", "deployments", TARGET)):
        base_resource, _, subresource = resource.partition("/")
        args = ["auth", "can-i", verb, base_resource]
        if name:
            args[-1] += f"/{name}"
        if subresource:
            args.append(f"--subresource={subresource}")
        args.extend(["--as", f"system:serviceaccount:{NAMESPACE}:{CONTROLLER}"])
        result = lab.kubectl(*args, allow_failure=True)
        access[f"{verb}:{resource}:{name or '*'}"] = result.stdout.strip()
    expected = {"get:configmaps:threshold-telemetry": "yes",
                "get:configmaps:threshold-policy": "yes",
                "get:configmaps:threshold-decision": "yes",
                "list:configmaps:*": "no",
                "patch:configmaps:threshold-decision": "yes",
                "patch:configmaps:threshold-policy": "no",
                f"patch:deployments/scale:{TARGET}": "yes",
                f"patch:deployments/scale:{CONTROL}": "no",
                f"patch:deployments:{TARGET}": "no"}
    lab.check("green", "Controller RBAC permits only named telemetry reads, decision writes and target scale patch",
              access == expected, {"can_i": access})

    (lab.evidence / "threshold-controller-observations.json").write_text(
        json.dumps({"disabled": disabled, "below_threshold": below,
                    "triggered_halt": halted, "persisted_after_restart": latched, "target_status": target_stopped,
                    "controller_pods_before": old_pods, "controller_pods_after": new_pods,
                    "target_ready_endpoints": target_endpoints,
                    "control_status": control_status, "control_ready_endpoints": control_endpoints,
                    "rbac_can_i": access, "checks": lab.checks}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
