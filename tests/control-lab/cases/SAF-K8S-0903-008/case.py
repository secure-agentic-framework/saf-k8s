"""Exercise deterministic budget reconciliation against a disposable Deployment."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "budget_reconciler.py"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0903-008"
CONTROL_ID = "SAF-K8S-0903-008"
CONTROLLER = "budget-reconciler"
WORKLOAD = "synthetic-inference"
SCOPE = (
    "One disposable Kind cluster using the harness-pinned Kubernetes v1.36.1 node image and one "
    "case-owned namespace. A Python 3.13 slim fixture evaluates fixed synthetic demand and spend, "
    "and a dedicated ServiceAccount may only get or patch the named Deployment's scale "
    "subresource. One inert CPU-only controller Pod and at most three inert CPU-only target Pods "
    "are present at once. Identical demand of three replicas and projected spend of $15.00 are "
    "compared with policy disabled and enabled; an actual over-cap HTTP 429, equal-cap, and recovery cases are also "
    "observed. No GPU, provider, cloud bill, external traffic, inference service, or production "
    "environment is involved."
)


def _kubectl(lab, *args, timeout=45, allow_failure=False, **kwargs):
    return lab.kubectl("-n", NAMESPACE, *args, timeout=timeout,
                       allow_failure=allow_failure, **kwargs)


def _apply(lab, obj):
    return json.loads(_kubectl(lab, "apply", "-f", "-", "-o", "json",
                               payload=json.dumps(obj)).stdout)


def _get(lab, kind, name):
    return json.loads(_kubectl(lab, "get", kind, name, "-o", "json").stdout)


def _wait_ready(lab, replicas, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _get(lab, "deployment", WORKLOAD)
        spec = last.get("spec", {}).get("replicas")
        ready = last.get("status", {}).get("readyReplicas", 0)
        available = last.get("status", {}).get("availableReplicas", 0)
        if spec == replicas and ready == replicas and available == replicas:
            return {"spec_replicas": spec, "ready_replicas": ready,
                    "available_replicas": available}
        time.sleep(2)
    lab.block(f"Target Deployment failed to reach {replicas} ready replicas: {last}")


def _invoke(lab, demand, enabled):
    data = json.dumps({"demand_replicas": demand, "budget_enabled": enabled},
                      separators=(",", ":"))
    code = """
import json
import sys
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

opener = build_opener(ProxyHandler({}))
request = Request("http://127.0.0.1:8080/evaluate", data=sys.argv[1].encode(),
                  headers={"Content-Type": "application/json"})
try:
    response = opener.open(request, timeout=18)
except HTTPError as error:
    response = error
with response:
    print(json.dumps({"http_status": response.status, **json.load(response)}))
"""
    output = _kubectl(lab, "exec", f"deployment/{CONTROLLER}", "--", "python", "-B",
                      "-c", code, data, timeout=25)
    try:
        receipt = json.loads(output.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Budget fixture returned an invalid JSON receipt: {error}")
    if receipt.get("http_status") not in {200, 429} or "requested_replicas" not in receipt:
        lab.block(f"Budget fixture could not apply an evaluation: {receipt}")
    return receipt


def _scenario(lab, demand, enabled):
    decision = _invoke(lab, demand, enabled)
    ready = _wait_ready(lab, decision.get("requested_replicas", -1))
    return {**decision, **ready}


def _rbac(lab):
    checks = {}
    for verb, resource, name, subresource in (
        ("get", "deployments", WORKLOAD, "scale"),
        ("patch", "deployments", WORKLOAD, "scale"),
        ("update", "deployments", WORKLOAD, "scale"),
        ("patch", "deployments", WORKLOAD, ""),
        ("patch", "deployments", "other-deployment", "scale"),
        ("create", "deployments", "", ""),
    ):
        target = f"{resource}/{name}" if name else resource
        flags = [f"--subresource={subresource}"] if subresource else []
        result = _kubectl(lab, "auth", "can-i", verb, target, *flags,
                          "--as", f"system:serviceaccount:{NAMESPACE}:{CONTROLLER}",
                          allow_failure=True)
        answer = result.stdout.strip()
        if (result.returncode, answer) not in {(0, "yes"), (1, "no")}:
            lab.block(f"Unexpected authorization response for {verb} {target}")
        canonical = "/".join(part for part in (resource, subresource, name) if part)
        checks[f"{verb} {canonical}"] = answer == "yes"
    return checks


def _manifest():
    labels = {"app": WORKLOAD, "saf.example/control": CONTROL_ID}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": WORKLOAD, "labels": labels},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": WORKLOAD}},
                     "template": {"metadata": {"labels": labels}, "spec": {
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "inert", "image": IMAGE,
                             "imagePullPolicy": "IfNotPresent",
                             "command": ["python", "-c", "import time; time.sleep(86400)"],
                             "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                           "limits": {"cpu": "100m", "memory": "64Mi"}},
                             "securityContext": {"allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "capabilities": {"drop": ["ALL"]}}}]}}}}


def _create_fixture(lab):
    _kubectl(lab, "create", "namespace", NAMESPACE)
    _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                 "metadata": {"name": CONTROLLER}})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": CONTROLLER}, "rules": [{
                     "apiGroups": ["apps"], "resources": ["deployments/scale"],
                     "resourceNames": [WORKLOAD], "verbs": ["get", "patch"]}]})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                 "metadata": {"name": CONTROLLER},
                 "subjects": [{"kind": "ServiceAccount", "name": CONTROLLER,
                               "namespace": NAMESPACE}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": CONTROLLER}})
    _apply(lab, _manifest())
    _kubectl(lab, "rollout", "status", f"deployment/{WORKLOAD}", "--timeout=120s",
             timeout=130)
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "budget-fixture"}, "immutable": True,
                 "data": {"budget_reconciler.py": FIXTURE.read_text(encoding="utf-8")}})
    _apply(lab, {"apiVersion": "apps/v1", "kind": "Deployment",
                 "metadata": {"name": CONTROLLER,
                              "labels": {"saf.example/control": CONTROL_ID}},
                 "spec": {"replicas": 1, "selector": {"matchLabels": {"app": CONTROLLER}},
                          "template": {"metadata": {"labels": {"app": CONTROLLER}},
                              "spec": {"serviceAccountName": CONTROLLER,
                                  "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                                      "seccompProfile": {"type": "RuntimeDefault"}},
                                  "containers": [{"name": "reconciler", "image": IMAGE,
                                      "imagePullPolicy": "IfNotPresent",
                                      "command": ["python", "/case/budget_reconciler.py"],
                                      "env": [{"name": "POD_NAMESPACE", "value": NAMESPACE}],
                                      "ports": [{"name": "http", "containerPort": 8080}],
                                      "readinessProbe": {"exec": {"command": ["python", "-B", "-c",
                                          "import socket; socket.create_connection(('127.0.0.1', 8080), 1).close()"]},
                                                         "periodSeconds": 2,
                                                         "failureThreshold": 30},
                                      "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                    "limits": {"cpu": "100m", "memory": "64Mi"}},
                                      "securityContext": {"allowPrivilegeEscalation": False,
                                          "readOnlyRootFilesystem": True,
                                          "capabilities": {"drop": ["ALL"]}},
                                      "volumeMounts": [{"name": "fixture", "mountPath": "/case",
                                                        "readOnly": True}]}],
                                  "volumes": [{"name": "fixture",
                                               "configMap": {"name": "budget-fixture"}}]}}}})
    _kubectl(lab, "rollout", "status", f"deployment/{CONTROLLER}", "--timeout=120s",
             timeout=130)


def run(lab):
    _create_fixture(lab)
    rbac = _rbac(lab)
    expected_rbac = {
        "get deployments/scale/synthetic-inference": True,
        "patch deployments/scale/synthetic-inference": True,
        "update deployments/scale/synthetic-inference": False,
        "patch deployments/synthetic-inference": False,
        "patch deployments/scale/other-deployment": False,
        "create deployments": False,
    }
    lab.check("positive", "The fixture identity has only the named Deployment scale permissions",
              rbac == expected_rbac, rbac)
    fixture = _verify_fixture_observation(lab)
    lab.check("positive", "The controller source and target are the case-owned pinned fixtures",
              _verify_fixture(fixture), fixture)

    red = _scenario(lab, demand=3, enabled=False)
    lab.check("red", "With budget policy off, identical $15 projected demand scales to three Ready Pods",
              red == {"http_status": 200, "demand_replicas": 3, "unit_cost": "5.00", "projected_spend": "15.00",
                      "approved_cap": "10.00", "budget_enabled": False, "allowed": True,
                      "requested_replicas": 3, "degraded_service": False, "decision": "allow",
                      "spec_replicas": 3, "ready_replicas": 3, "available_replicas": 3}, red)

    reset = _scenario(lab, demand=1, enabled=True)
    lab.check("positive", "The under-cap reset returns the target to one Ready Pod",
              reset["requested_replicas"] == 1 and reset["http_status"] == 200 and reset["ready_replicas"] == 1
              and reset["projected_spend"] == "5.00" and reset["allowed"], reset)

    green = _scenario(lab, demand=3, enabled=True)
    lab.check("green", "The same $15 demand over the $10 cap suppresses scale-up and selects degraded service",
              green == {"http_status": 429, "demand_replicas": 3, "unit_cost": "5.00", "projected_spend": "15.00",
                        "approved_cap": "10.00", "budget_enabled": True, "allowed": False,
                        "requested_replicas": 1, "degraded_service": True,
                        "decision": "suppress_scale_up_and_degrade", "spec_replicas": 1,
                        "ready_replicas": 1, "available_replicas": 1}, green)

    equal = _scenario(lab, demand=2, enabled=True)
    lab.check("positive", "Projected spend exactly equal to the approved cap remains allowed",
              equal["projected_spend"] == equal["approved_cap"] == "10.00"
              and equal["http_status"] == 200 and equal["allowed"] and not equal["degraded_service"]
              and equal["spec_replicas"] == equal["ready_replicas"] == 2, equal)

    over = _scenario(lab, demand=3, enabled=True)
    lab.check("green", "Over-cap scale-up is blocked while existing Ready capacity is retained",
              over["projected_spend"] == "15.00" and over["approved_cap"] == "10.00"
              and not over["allowed"] and over["degraded_service"]
              and over["http_status"] == 429 and over["requested_replicas"] == over["spec_replicas"] == over["ready_replicas"] == 2,
              over)

    recovery = _scenario(lab, demand=1, enabled=True)
    lab.check("positive", "When projected spend recovers below cap, scaling down remains allowed",
              recovery["projected_spend"] == "5.00" and recovery["allowed"]
              and recovery["http_status"] == 200 and not recovery["degraded_service"]
              and recovery["requested_replicas"] == recovery["spec_replicas"]
              == recovery["ready_replicas"] == 1, recovery)


def _verify_fixture(facts):
    return (facts["source_matches"] and facts["target_image_is_pinned"]
            and facts["controller_image_is_pinned"]
            and facts["target_pod_token_mounted"] is False
            and facts["controller_service_account"] == CONTROLLER
            and facts["role_rules"] == [{"apiGroups": ["apps"],
                                          "resources": ["deployments/scale"],
                                          "resourceNames": [WORKLOAD],
                                          "verbs": ["get", "patch"]}])


def _verify_fixture_observation(lab):
    config = _get(lab, "configmap", "budget-fixture")
    target = _get(lab, "deployment", WORKLOAD)
    controller = _get(lab, "deployment", CONTROLLER)
    role = _get(lab, "role", CONTROLLER)
    pod = target["spec"]["template"]["spec"]
    container = pod["containers"][0]
    fixture_pod = controller["spec"]["template"]["spec"]
    fixture_container = fixture_pod["containers"][0]
    source_matches = config.get("data", {}).get("budget_reconciler.py") == FIXTURE.read_text(encoding="utf-8")
    return {"source_matches": source_matches,
            "target_image": container.get("image"), "controller_image": fixture_container.get("image"),
            "target_pod_token_mounted": pod.get("automountServiceAccountToken"),
            "controller_service_account": fixture_pod.get("serviceAccountName"),
            "target_command": container.get("command"),
            "role_rules": role.get("rules"),
            "target_image_is_pinned": container.get("image") == IMAGE,
            "controller_image_is_pinned": fixture_container.get("image") == IMAGE}
