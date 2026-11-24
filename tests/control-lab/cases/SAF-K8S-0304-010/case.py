"""Contrast pre-admission declarations with Kubernetes admission/defaulting."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import time

from fixtures import container, pod, ready

SCOPE = ("Explicit CPU, memory and ephemeral-storage declarations for regular and init containers. "
         "The source check sees the raw manifest. Admission sees defaulted resource values. "
         "An upstream kubelet device plugin supplies exactly two synthetic device allocations without GPU hardware.")
HERE = Path(__file__).parent
CHECKER = HERE / "resource-declarations.py"
RESOURCES = {
    "requests": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "128Mi"},
    "limits": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "512Mi"},
}


def workload(name, regular=RESOURCES, init=RESOURCES):
    return pod(
        name,
        [container("regular", resources=regular)],
        initContainers=[container("initializer", resources=init, command=["sh", "-c", "exit 0"])],
    )


def source_check(resource):
    result = subprocess.run([sys.executable, str(CHECKER)], input=json.dumps(resource),
                            text=True, capture_output=True, timeout=10)
    return result.returncode, result.stdout.strip() or result.stderr.strip()


def admitted_resources(observed):
    return [observed["spec"][key][0]["resources"] for key in ("containers", "initContainers")]


def denied(result, container_class):
    return (
        result.returncode != 0
        and "(Forbidden)" in result.stderr
        and "saf-k8s-0304-010-bounded-resources" in result.stderr
        and f"each {container_class} container must declare" in result.stderr
    )


def run(lab):
    omitted = {
        "regular": workload("omit-regular", regular={}),
        "init": workload("omit-init", init={}),
    }
    for container_class, probe in omitted.items():
        data = admitted_resources(lab.create(probe, dry_run=True))
        index = 0 if container_class == "regular" else 1
        lab.check("red", f"API admits an unbounded {container_class} container before policy",
                  data[index] == {}, data)

    limits_only = {"limits": RESOURCES["limits"]}
    omitted_requests = workload("limits-only", regular=limits_only, init=limits_only)
    data = admitted_resources(lab.create(omitted_requests, dry_run=True))
    defaulted = {"requests": RESOURCES["limits"], "limits": RESOURCES["limits"]}
    lab.check("red", "Kubernetes copies limits to requests before validating admission",
              all(resources == defaulted for resources in data), data)
    code, message = source_check(omitted_requests)
    lab.check("green", "Source checker catches omitted requests for both container classes",
              code == 1 and "containers/regular missing requests.cpu" in message
              and "initContainers/initializer missing requests.cpu" in message, message)

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        result = lab.create(omitted["regular"], dry_run=True, allow_failure=True)
        if denied(result, "regular") or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    for container_class, probe in omitted.items():
        result = lab.create(probe, dry_run=True, allow_failure=True)
        lab.check("green", f"Admission rejects an unbounded {container_class} container",
                  denied(result, container_class), result.stderr.strip())

    data = admitted_resources(lab.create(omitted_requests, dry_run=True))
    lab.check("green", "Admission still accepts the API-defaulted requests",
              all(resources == defaulted for resources in data), data)

    valid = workload("valid-resources")
    code, message = source_check(valid)
    lab.check("positive", "Source checker accepts explicit regular and init declarations",
              code == 0, message)
    lab.create(valid)
    ready(lab, "valid-resources")
    stored = json.loads(lab.kubectl("get", "pod", "valid-resources", "-o", "json").stdout)
    status = stored["status"]
    ready_status = status["phase"] == "Running" and any(
        condition["type"] == "Ready" and condition["status"] == "True"
        for condition in status["conditions"]
    )
    lab.check("positive", "A Pod reaches Ready with the authored regular and init declarations",
              ready_status and all(resources == RESOURCES for resources in admitted_resources(stored)),
              {"running_and_ready": ready_status, "resources_match_authored": all(
                  resources == RESOURCES for resources in admitted_resources(stored))})
    quota, period = lab.kubectl("exec", "valid-resources", "-c", "regular", "--",
                                "cat", "/sys/fs/cgroup/cpu.max").stdout.split()
    memory = lab.kubectl("exec", "valid-resources", "-c", "regular", "--",
                         "cat", "/sys/fs/cgroup/memory.max").stdout.strip()
    cpu_matches = quota.isdigit() and period.isdigit() and int(quota) * 2 == int(period) > 0
    memory_matches = memory.isdigit() and int(memory) == 256 * 1024 * 1024
    lab.check("positive", "The running fixture exposes its CPU quota and memory ceiling",
              cpu_matches and memory_matches,
              {"cpu_quota_matches_500m": cpu_matches, "memory_ceiling_matches_256Mi": memory_matches})

    accelerator = runpy.run_path(str(HERE / "accelerator" / "case.py"))
    accelerator["run"](lab)
