"""Validate deterministic inference bounds in a disposable single Kind cluster."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
NAME = "inference-fixture"
PORT = 8080
SCOPE = (
    "One default Kubernetes v1.36.1 Kind cluster runs a digest-pinned Python fixture. "
    "The fixture executes fixed, small synthetic compute and records deterministic backend "
    "counters for exact input size, request work/deadline, cumulative session work/deadline, "
    "batch size/deadline, and a fixture-controlled overload/degradation decision. The clock, "
    "work units, occupancy, and releases are synthetic; this is application-policy evidence, "
    "not wall-clock latency, accelerator behavior, a deployed inference server, or a production "
    "circuit breaker. Kubernetes CPU/memory container limits are inspected separately from "
    "extended-resource quantity. Real GPU memory ceilings, device-plugin/MIG behavior, cloud "
    "quotas/costs, ingress/service-mesh configuration, and production policy require separate "
    "evidence."
)


def wait_ready(lab, mode):
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-l", "app=" + NAME, "-o", "json")
        pods = json.loads(result.stdout)["items"]
        if len(pods) == 1 and pods[0].get("status", {}).get("phase") == "Running":
            env = pods[0]["spec"]["containers"][0]["env"]
            if {"name": "POLICY_MODE", "value": mode} not in env:
                time.sleep(0.4)
                continue
            conditions = pods[0]["status"].get("conditions", [])
            if any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
                return pods[0]
        time.sleep(0.4)
    lab.block("Inference fixture did not become ready")


def deploy(lab, mode):
    container = {
        "name": "fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-B", "/fixture/fixture.py", "serve"],
        "env": [{"name": "POLICY_MODE", "value": mode}],
        "ports": [{"name": "http", "containerPort": PORT}],
        "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                           "periodSeconds": 1, "failureThreshold": 20},
    }
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": NAME},
                "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                         "selector": {"matchLabels": {"app": NAME}},
                         "template": {"metadata": {"labels": {"app": NAME}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True,
                                                                   "runAsUser": 65534,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "volumes": [{"name": "code",
                                                            "configMap": {"name": "inference-code"}}],
                                               "containers": [container]}}}})
    lab.kubectl("rollout", "status", "deployment/" + NAME, "--timeout=75s", timeout=85)
    return wait_ready(lab, mode)


def observe(lab, pod, mode):
    expected_uid = pod["metadata"]["uid"]
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        slices = lab.kubectl("get", "endpointslice", "-l",
                            "kubernetes.io/service-name=" + NAME, "-o", "json")
        ready = [endpoint.get("targetRef", {}).get("uid")
                 for item in json.loads(slices.stdout)["items"]
                 for endpoint in (item.get("endpoints") or [])
                 if endpoint.get("conditions", {}).get("ready") is True]
        if ready == [expected_uid]:
            break
        time.sleep(0.25)
    else:
        lab.block("Inference Service did not target the current Ready fixture Pod")
    client = (HERE / "observe.py").read_text()
    result = lab.kubectl("exec", "-i", "pod/" + pod["metadata"]["name"], "--",
                         "python", "-B", "-", payload=client, timeout=30)
    try:
        report = json.loads(result.stdout)
        if report.get("fixture_id") != "SAF-K8S-0903-003-synthetic-v1" or report.get("mode") != mode:
            lab.block("The inference Service returned the wrong fixture or policy mode")
        return report
    except (AttributeError, json.JSONDecodeError) as error:
        lab.block("Fixture returned invalid observation JSON: " + str(error))


def run(lab):
    code = (HERE / "fixture.py").read_text()
    configmap = lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": {"name": "inference-code"}, "immutable": True,
                            "data": {"fixture.py": code}})
    if configmap.get("data", {}).get("fixture.py") != code or not configmap.get("immutable"):
        lab.block("Kubernetes did not retain the exact immutable fixture source")
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": NAME},
                "spec": {"selector": {"app": NAME},
                         "ports": [{"name": "http", "port": PORT, "targetPort": "http"}]}})

    pod = deploy(lab, "weak")
    weak = observe(lab, pod, "weak")
    weak_bounds = weak.get("results", {})
    weak_bad = (weak.get("mode") == "weak"
                and weak_bounds.get("oversize", {}).get("status") == 200
                and weak_bounds.get("request_budget", {}).get("status") == 200
                and weak_bounds.get("session_budget", {}).get("status") == 200
                and all(weak_bounds.get(name, {}).get("status") == 200 for name in (
                    "batch_budget", "request_timeout", "session_timeout", "batch_timeout"))
                and weak_bounds["oversize"].get("input_bytes") == 65
                and weak_bounds["request_budget"].get("work_units") == 4)
    lab.check("red", "The deliberately weak policy admits bounded over-limit fixtures",
              weak_bad, {"mode": weak.get("mode"), "oversize": weak_bounds.get("oversize"),
                         "request_budget": weak_bounds.get("request_budget"),
                         "session_budget": weak_bounds.get("session_budget"),
                         "request_timeout": weak_bounds.get("request_timeout")})

    lab.kubectl("delete", "deployment", NAME, "--wait=true", timeout=30)
    pod = deploy(lab, "strong")
    strong = observe(lab, pod, "strong")
    (lab.evidence / "inference-bounds.raw.json").write_text(
        json.dumps({"weak": weak, "strong": strong}, indent=2) + "\n")
    results = strong.get("results", {})
    expected = {
        "oversize": (413, "input_limit"),
        "request_budget": (429, "request_budget"),
        "session_budget": (429, "session_budget"),
        "batch_budget": (413, "batch_limit"),
        "request_timeout": (504, "request_timeout"),
        "session_timeout": (504, "session_timeout"),
        "batch_timeout": (504, "batch_timeout"),
    }
    matched = {key: results.get(key, {}).get("status") == status
               and results.get(key, {}).get("reason") == reason
               for key, (status, reason) in expected.items()}
    counters = strong.get("counters", {})
    counter_ok = (counters.get("input_rejected") == 1
                  and counters.get("request_budget_rejected") == 1
                  and counters.get("session_budget_rejected") == 1
                  and counters.get("batch_budget_rejected") == 1
                  and counters.get("request_timeout") == 1
                  and counters.get("session_timeout") == 1
                  and counters.get("batch_timeout") == 1
                  and counters.get("work_units_executed") == 6)
    lab.check("green", "The strong policy enforces independent budgets and virtual deadlines",
              strong.get("mode") == "strong" and all(matched.values()) and counter_ok,
              {"scenario_matches": matched, "authoritative_backend_counters": counters,
               "expected_work_units": 6})

    positive = results.get("exact_boundary", {})
    overload = results.get("overload", {})
    container = pod["spec"]["containers"][0]
    resource = container.get("resources", {})
    running_image = container.get("image") == IMAGE
    ready_pod = pod.get("status", {}).get("phase") == "Running" and any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in pod.get("status", {}).get("conditions", []))
    positive_ok = (positive.get("status") == 200
                   and positive.get("reason") == "accepted"
                   and positive.get("input_bytes") == 64
                   and positive.get("work_units") == 2
                   and overload.get("status") == 200
                   and overload.get("reason") == "degraded"
                   and overload.get("quality") == "reduced"
                   and resource.get("limits") == {"cpu": "200m", "memory": "96Mi"}
                   and resource.get("requests") == {"cpu": "10m", "memory": "24Mi"}
                   and "nvidia.com/gpu" not in resource.get("limits", {})
                   and running_image and ready_pod)
    lab.check("positive", "Exact-size inference succeeds and the fixed overload selects reduced quality",
              positive_ok, {"exact_boundary": positive, "overload": overload,
                            "kubernetes_container_resources": resource,
                            "extended_gpu_resource_requested": "nvidia.com/gpu" in resource.get("limits", {}),
                            "digest_pinned_fixture_image": running_image,
                            "pod_running_and_ready": ready_pod})
