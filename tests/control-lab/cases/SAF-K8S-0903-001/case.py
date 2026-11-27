"""SAF-K8S-0903-001: defensive serving and explanation access control fixture."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
NS = "saf-test"
APP = "saf-0903-inference"
BACKEND = "saf-0903-model-backend"
VALIDATOR = "saf-0903-validator"
PORT = 8080
EXPLAIN_PORT = 8081
BACKEND_PORT = 8082
VALIDATOR_PORT = 8083
MARKED_INPUT = {"text": "ordinary benign fixture", "fixture_marker": "FIXTURE:REJECT-0903"}
CLEAN_INPUT = {"text": "ordinary benign fixture", "fixture_marker": "FIXTURE:CLEAN-0903"}
EXPLANATION_REQUEST = {"request_id": "bounded-fixture-v1"}
SCOPE = (
    "One Kubernetes v1.36.1 Kind cluster with enforcing NetworkPolicy. Two case-owned workloads implement "
    "an inert inference stand-in and a fixed synthetic explanation. Compare the same marked benign request before "
    "and after deterministic rejection, check the backend counter and content-free rejection record, then compare "
    "a named ordinary Pod and a monitoring-labeled Pod accessing the same explanation port. A clean inference "
    "request remains functional. Then verify a fixed explanation disclosure budget and a safe serving response "
    "during the loss and return of the owned validation dependency. Model effectiveness, deployed identity and "
    "label governance, alternate paths, distributed disclosure limits and audit retention require separate evidence."
)


def service_pod(lab, mode):
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-n", NS, "-l", "app=" + APP, "-o", "json")
        pods = json.loads(result.stdout).get("items") or []
        if len(pods) == 1:
            pod = pods[0]
            env = pod["spec"]["containers"][0].get("env", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod.get("status", {}).get("conditions", []))
            if (pod.get("status", {}).get("phase") == "Running" and ready
                    and {"name": "REJECT_MARKER", "value": "true" if mode == "enabled" else "false"} in env):
                return pod
        time.sleep(0.4)
    lab.block("Inference fixture did not become ready in the requested policy mode")


def deploy(lab, mode, *, with_dependencies=False):
    container = {
        "name": "service", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-B", "/fixture/fixture.py"],
        "env": [{"name": "REJECT_MARKER", "value": "true" if mode == "enabled" else "false"},
                {"name": "BACKEND_URL", "value": f"http://{BACKEND}:{BACKEND_PORT}"}],
        "ports": [{"name": "http", "containerPort": PORT},
                  {"name": "explain", "containerPort": EXPLAIN_PORT}],
        "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                           "periodSeconds": 1, "failureThreshold": 20},
    }
    if with_dependencies:
        container["env"].extend([
            {"name": "VALIDATION_URL", "value": f"http://{VALIDATOR}:{VALIDATOR_PORT}"},
            {"name": "EXPLANATION_BUDGET", "value": "2"},
        ])
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": APP, "namespace": NS},
                "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                         "selector": {"matchLabels": {"app": APP}},
                         "template": {"metadata": {"labels": {"app": APP}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "volumes": [{"name": "code", "configMap": {"name": "fixture-code"}}],
                                               "containers": [container]}}}})
    lab.kubectl("rollout", "status", "deployment/" + APP, "-n", NS, "--timeout=75s", timeout=85)
    return service_pod(lab, mode)


def deploy_dependency(lab, name, port, mode):
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": name, "namespace": NS},
                "spec": {"replicas": 1,
                         "selector": {"matchLabels": {"app": name}},
                         "template": {"metadata": {"labels": {"app": name}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "volumes": [{"name": "code", "configMap": {"name": "fixture-code"}}],
                                               "containers": [{"name": mode, "image": IMAGE,
                                                   "imagePullPolicy": "IfNotPresent",
                                                   "command": ["python", "-B", "/fixture/fixture.py", mode],
                                                   "ports": [{"name": mode, "containerPort": port}],
                                                   "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}],
                                                   "securityContext": {"allowPrivilegeEscalation": False,
                                                       "readOnlyRootFilesystem": True,
                                                       "capabilities": {"drop": ["ALL"]}},
                                                   "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                       "limits": {"cpu": "200m", "memory": "96Mi"}},
                                                   "readinessProbe": {"httpGet": {"path": "/health", "port": mode},
                                                       "periodSeconds": 1, "failureThreshold": 20}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": NS},
                "spec": {"selector": {"app": name},
                         "ports": [{"name": mode, "port": port, "targetPort": mode}]}})
    response = lab.kubectl("rollout", "status", "deployment/" + name, "-n", NS,
                           "--timeout=50s", timeout=60, allow_failure=True)
    if response.returncode:
        lab.kubectl("get", "pods", "-l", f"app={name}", "-o", "wide", allow_failure=True)
        lab.kubectl("logs", f"deployment/{name}", "--tail=30", allow_failure=True)
        lab.block(f"Case dependency {name} did not become ready")


def replace_service(lab, mode, *, with_dependencies=False):
    lab.kubectl("delete", "deployment", APP, "-n", NS, "--wait=true", timeout=30)
    return deploy(lab, mode, with_dependencies=with_dependencies)


def call(lab, pod, path, body=None, *, port=PORT, service=APP):
    url = f"http://{service}.{NS}.svc.cluster.local:{port}{path}"
    payload = json.dumps({"url": url, "body": body}, separators=(",", ":"))
    client_source = (HERE / "client.py").read_text().replace("__CASE_REQUEST__", repr(payload))
    result = lab.kubectl("exec", "-i", "-n", NS, "pod/" + pod, "--", "python", "-B", "-",
                         payload=client_source,
                         timeout=20)
    try:
        return json.loads(result.stdout)
    except (AttributeError, json.JSONDecodeError) as error:
        lab.block("Client fixture returned invalid JSON: " + str(error))


def counters(lab, pod):
    frontend = call(lab, pod, "/admin/counters", {})
    backend = call(lab, "monitor-client", "/count", port=BACKEND_PORT, service=BACKEND)
    if frontend.get("status") != 200 or backend.get("status") != 200:
        lab.block("Fixture counters could not be read from both workloads")
    return {**frontend["body"], **backend["body"]}


def run(lab):
    fixture = (HERE / "fixture.py").read_text()
    cm = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-code", "namespace": NS},
                     "immutable": True, "data": {"fixture.py": fixture}})
    if cm.get("data", {}).get("fixture.py") != fixture or not cm.get("immutable"):
        lab.block("Kubernetes did not retain the exact immutable fixture source")
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": APP, "namespace": NS},
                "spec": {"selector": {"app": APP}, "ports": [
                    {"name": "http", "port": PORT, "targetPort": "http"},
                    {"name": "explain", "port": EXPLAIN_PORT, "targetPort": "explain"}]}})
    for name, role in (("ordinary-client", "ordinary"), ("monitor-client", "monitor")):
        lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS,
                    "labels": {"case-role": role}},
                    "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "client", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                             "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                                             "securityContext": {"allowPrivilegeEscalation": False,
                                                                 "readOnlyRootFilesystem": True,
                                                                 "capabilities": {"drop": ["ALL"]}},
                                             "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                           "limits": {"cpu": "100m", "memory": "48Mi"}}}]}})
        lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "-n", NS, "--timeout=95s", timeout=105)

    ordinary = "ordinary-client"
    monitor = "monitor-client"
    deploy_dependency(lab, BACKEND, BACKEND_PORT, "backend")
    deploy(lab, "disabled")
    weak = call(lab, ordinary, "/infer", MARKED_INPUT)
    weak_counts = counters(lab, ordinary)
    lab.check("red", "With input rejection disabled the fixed marked request reaches inference",
              weak.get("status") == 200 and weak_counts.get("backend_calls") == 1
              and weak_counts.get("rejections") == 0,
              {"response": weak, "backend_counters": weak_counts})

    replace_service(lab, "enabled")
    rejected = call(lab, ordinary, "/infer", MARKED_INPUT)
    strict_counts = counters(lab, ordinary)
    record = {"rejection_id": "reject-0903-0001", "reason": "fixture_marker_rejected"}
    lab.check("green", "Enabled rejection blocks inference and retains only the fixed ID and reason",
              rejected == {"status": 422, "body": record}
              and strict_counts["backend_calls"] == weak_counts["backend_calls"] and strict_counts["rejections"] == 1
              and strict_counts["rejection_records"] == [record],
              {"response": rejected, "counters": strict_counts})

    explanation_value = {"fixture_id": "SAF-K8S-0903-001-benign-v1",
                         "features": [{"name": "signal_a", "value": 0.25}, {"name": "signal_b", "value": 0.75}]}
    explanation_before = call(lab, ordinary, "/explain", EXPLANATION_REQUEST, port=EXPLAIN_PORT)
    counts_before_policy = counters(lab, ordinary)
    lab.check("red", "Without network isolation the ordinary Pod reaches the exact explanation listener",
              explanation_before == {"status": 200, "body": explanation_value}
              and counts_before_policy["explanation_calls"] == 1,
              {"response": explanation_before, "explanation_calls": counts_before_policy["explanation_calls"]})
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
              "metadata": {"name": "explanation-monitor-only", "namespace": NS},
              "spec": {"podSelector": {"matchLabels": {"app": APP}}, "policyTypes": ["Ingress"],
                       "ingress": [
                           {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}}],
                            "ports": [{"protocol": "TCP", "port": PORT}]},
                           {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
                                      "podSelector": {"matchLabels": {"case-role": "monitor"}}}],
                            "ports": [{"protocol": "TCP", "port": EXPLAIN_PORT}]}]}}
    lab.create(policy)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        restricted = call(lab, ordinary, "/health", port=EXPLAIN_PORT)
        if restricted == {"transport": "timeout"}:
            break
        time.sleep(0.4)
    explanation_after = call(lab, ordinary, "/explain", EXPLANATION_REQUEST, port=EXPLAIN_PORT)
    monitor_after = call(lab, monitor, "/explain", EXPLANATION_REQUEST, port=EXPLAIN_PORT)
    inference_listener = call(lab, ordinary, "/explain", EXPLANATION_REQUEST, port=PORT)
    counts_after_policy = counters(lab, ordinary)
    lab.check("green", "Only the monitoring Pod receives explanation output through the designated listener",
              explanation_after == {"transport": "timeout"}
              and monitor_after == {"status": 200, "body": explanation_value}
              and inference_listener == {"status": 404, "body": {"reason": "not_found"}}
              and counts_after_policy["explanation_calls"] == 2,
              {"ordinary_listener": explanation_after, "monitor_listener": monitor_after,
               "inference_listener": inference_listener, "explanation_calls": counts_after_policy["explanation_calls"]})

    clean = call(lab, ordinary, "/infer", CLEAN_INPUT)
    final_counts = counters(lab, ordinary)
    lab.check("positive", "Ordinary inference still runs after both controls are enabled",
              clean == {"status": 200, "body": {"prediction": "fixture-class", "backend_call": 2}}
              and final_counts["backend_calls"] == 2 and final_counts["rejections"] == 1
              and final_counts["rejection_records"] == [record],
              {"response": clean, "counters": final_counts})

    (lab.evidence / "serving-defense.json").write_text(json.dumps({
        "disabled_marker": {"response": weak, "counters": weak_counts},
        "enabled_marker": {"response": rejected, "counters": strict_counts},
        "clean_request": {"response": clean, "counters": final_counts},
        "explanation": {"before": explanation_before, "ordinary_after": explanation_after,
                        "monitor_after": monitor_after, "inference_listener": inference_listener,
                        "counters_before": counts_before_policy, "counters_after": counts_after_policy}},
        indent=2, sort_keys=True) + "\n")


    deploy_dependency(lab, VALIDATOR, VALIDATOR_PORT, "validation")
    replace_service(lab, "enabled", with_dependencies=True)
    explanation_responses = [call(lab, monitor, "/explain", EXPLANATION_REQUEST, port=EXPLAIN_PORT)
                             for _ in range(3)]
    explanation_count = counters(lab, ordinary)["explanation_calls"]
    (lab.evidence / "explanation-policy-observations.json").write_text(json.dumps({
        "fixture_disclosures_allowed": 2, "scope": "single-serving-process",
        "authorized_path_responses": explanation_responses, "observed_disclosures": explanation_count,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("explanation_disclosure_budget", "The designated explanation listener limits disclosed fixture responses",
              explanation_responses == [{"status": 200, "body": explanation_value}] * 2
              + [{"status": 429, "body": {"reason": "fixture_disclosure_budget_exhausted"}}]
              and explanation_count == 2,
              {"responses": explanation_responses, "observed_disclosures": explanation_count})
    verify_validation_dependency(lab, ordinary)


def ready_validator_addresses(lab):
    response = lab.kubectl("get", "endpointslice", "-n", NS, "-o", "json",
                           "-l", f"kubernetes.io/service-name={VALIDATOR}")
    return sorted(address for item in json.loads(response.stdout)["items"] for endpoint in (item.get("endpoints") or [])
                  if endpoint.get("conditions", {}).get("ready") is True for address in endpoint["addresses"])


def await_validator(lab, expected_ready):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        addresses = ready_validator_addresses(lab)
        if bool(addresses) == expected_ready:
            return addresses
        time.sleep(0.4)
    lab.block(f"Owned validation Service readiness did not reach {expected_ready}")


def await_validator_stopped(lab):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "pod", "-n", NS, "-l", f"app={VALIDATOR}", "-o", "json")
        if not json.loads(response.stdout)["items"]:
            return []
        time.sleep(0.5)
    lab.block("The owned validation Pod did not finish terminating")


def verify_validation_dependency(lab, ordinary):
    ready_before = await_validator(lab, True)
    accepted_before = call(lab, ordinary, "/infer", CLEAN_INPUT)
    before = counters(lab, ordinary)["backend_calls"]
    lab.kubectl("scale", f"deployment/{VALIDATOR}", "-n", NS, "--replicas=0")
    stopped_pods = await_validator_stopped(lab)
    stopped = await_validator(lab, False)
    during_fault = call(lab, ordinary, "/infer", CLEAN_INPUT)
    during = counters(lab, ordinary)["backend_calls"]
    lab.kubectl("scale", f"deployment/{VALIDATOR}", "-n", NS, "--replicas=1")
    lab.kubectl("rollout", "status", f"deployment/{VALIDATOR}", "-n", NS, "--timeout=60s", timeout=70)
    ready_after = await_validator(lab, True)
    accepted_after = call(lab, ordinary, "/infer", CLEAN_INPUT)
    rejected_after = call(lab, ordinary, "/infer", MARKED_INPUT)
    after = counters(lab, ordinary)["backend_calls"]
    observed = {
        "healthy_before": accepted_before == {"status": 200, "body": {
            "prediction": "fixture-class", "backend_call": before}},
        "fault_returns_defined_error": during_fault == {"status": 503, "body": {
            "reason": "fixture_validation_unavailable"}},
        "no_backend_call_during_fault": before == during,
        "permitted_input_restored": accepted_after == {"status": 200, "body": {
            "prediction": "fixture-class", "backend_call": before + 1}},
        "fixed_negative_still_rejected_without_backend_call": rejected_after == {"status": 422, "body": {
            "rejection_id": "reject-0903-0001", "reason": "fixture_marker_rejected"}} and after == before + 1,
    }
    (lab.evidence / "validation-failure-recovery.json").write_text(json.dumps({
        "validator_pods_after_scale_down": stopped_pods,
        "validator_ready_addresses": {"before": ready_before, "fault": stopped, "recovered": ready_after},
        "responses": {"before": accepted_before, "fault": during_fault, "accepted_after": accepted_after,
                      "rejected_after": rejected_after},
        "backend_calls": {"before": before, "fault": during, "recovered": after},
        "observed": observed,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("validation_dependency_safe_failure", "Losing the validation dependency stops forwarding and then recovers",
              all(observed.values()), observed)
