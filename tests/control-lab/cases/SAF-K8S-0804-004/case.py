"""Verify a declared runtime resource budget with two inert workload runs."""

import hashlib
import json
import time

SCOPE = "Actual Kubernetes RuntimeClass overhead accounting and fixture completion, with no confidential runtime or GPU."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
RUNTIME = "fixture-reviewed-runtime"
QUOTA = "fixture-workload-budget"
REQUEST = "requests.cpu"
PAYLOAD = "fixture-readiness-work"


def workload(name, runtime=None):
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "fixture", "image": IMAGE,
                            "command": ["python", "-c", "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())", PAYLOAD],
                            "resources": {"requests": {"cpu": "100m", "memory": "16Mi"},
                                          "limits": {"cpu": "200m", "memory": "40Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}}}]}
    if runtime:
        spec["runtimeClassName"] = runtime
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def quota(lab, expected_hard, *, require_empty=True):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        current = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)["status"]
        if current.get("hard", {}).get(REQUEST) == expected_hard and (not require_empty or current.get("used", {}).get(REQUEST) == "0"):
            return
        time.sleep(0.4)
    lab.block("The quota controller did not publish the required budget and usage")


def complete(lab, input_pod):
    name = input_pod["metadata"]["name"]
    started = time.monotonic()
    lab.create(input_pod)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=60s", timeout=70)
    recorded = lab.kubectl("logs", name).stdout.strip()
    effective = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["spec"]
    return recorded, effective.get("overhead", {}), round(time.monotonic() - started, 3)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass", "metadata": {"name": RUNTIME}, "handler": "runc",
                "overhead": {"podFixed": {"cpu": "60m", "memory": "8Mi"}}})
    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA},
                "spec": {"hard": {REQUEST: "150m"}}})
    quota(lab, "150m")
    standard = workload("fixture-standard")
    elevated = workload("fixture-with-overhead", RUNTIME)
    base_pass = lab.create(standard, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "The baseline workload fits the original budget without runtime overhead",
              base_pass, {"baseline_admitted_to_initial_budget": base_pass})
    denied = lab.create(elevated, dry_run=True, allow_failure=True)
    constrained = denied.returncode != 0 and "exceeded quota" in denied.stderr and "160m" in denied.stderr
    lab.check("green", "The same workload with declared overhead is refused by the original budget",
              constrained, {"modeled_runtime_requests_160m_and_is_denied": constrained})

    lab.kubectl("patch", "resourcequota", QUOTA, "--type=merge", "-p", json.dumps({"spec": {"hard": {REQUEST: "180m"}}}))
    quota(lab, "180m")
    base_result, base_overhead, base_duration = complete(lab, standard)
    lab.kubectl("delete", "pod", "fixture-standard", "--wait=true")
    quota(lab, "180m")
    reviewed, reviewed_overhead, reviewed_duration = complete(lab, elevated)
    expected = hashlib.sha256(PAYLOAD.encode()).hexdigest()
    exact_results = base_result == reviewed == expected
    lab.check("positive", "Both actual workload runs produce the same result after capacity is approved",
              exact_results and base_overhead == {} and reviewed_overhead == {"cpu": "60m", "memory": "8Mi"},
              {"matching_results": exact_results, "runtime_overhead_recorded": reviewed_overhead == {"cpu": "60m", "memory": "8Mi"}})
    (lab.evidence / "runtime-budget-observations.json").write_text(json.dumps({
        "original_quota": "150m", "adjusted_quota": "180m", "base_declared_request": "100m",
        "observed_runtime_overhead": reviewed_overhead, "matching_results": exact_results,
        "local_submit_to_completion_seconds": {"baseline": base_duration, "modeled_runtime": reviewed_duration},
        "hardware_overhead_measured": False}, indent=2) + "\n")
