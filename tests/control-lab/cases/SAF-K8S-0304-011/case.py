"""Exercise namespace LimitRange defaults/maxima and request quotas."""
import json
import time
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).parent
QUOTA_NAME = "saf-0304-request-budget"
SCOPE = (
    "One saf-test namespace on the lab's pinned kind Kubernetes v1.36.1: server-side "
    "Pod admission applies LimitRange default requests and limits and denies per-container "
    "CPU, memory, or ephemeral-storage limits above configured maxima; two harmless, "
    "small Pods consume aggregate requests.cpu, requests.memory, and "
    "requests.ephemeral-storage quota, and separate dry-run candidates exceed each quota. "
    "This demonstrates API admission and declared-request accounting only. It does not "
    "measure live CPU, memory, or disk consumption, provide GPU hardware or device-plugin "
    "evidence, validate policy governance, or establish namespace-wide rollout."
)

DEFAULTS = {
    "requests": {"cpu": "10m", "memory": "8Mi", "ephemeral-storage": "8Mi"},
    "limits": {"cpu": "20m", "memory": "16Mi", "ephemeral-storage": "16Mi"},
}
BASE_REQUESTS = {"cpu": "40m", "memory": "16Mi", "ephemeral-storage": "16Mi"}
BASE_LIMITS = {"cpu": "80m", "memory": "32Mi", "ephemeral-storage": "32Mi"}
QUOTA_HARD = {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "64Mi"}


def workload(name, *, requests=None, limits=None):
    """Build an idle, non-root Pod from the lab's shared bounded fixture helper."""
    resources = {}
    if requests is not None:
        resources["requests"] = requests
    if limits is not None:
        resources["limits"] = limits
    return pod(name, [container("probe", **({"resources": resources} if resources else {}))])


def resources_of(admitted):
    return admitted["spec"]["containers"][0].get("resources", {})


def forbidden(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr


def limit_denial(result, resource):
    message = result.stderr
    return (
        forbidden(result)
        and resource in message
        and ("maximum" in message.lower() or "less than or equal" in message.lower())
    )


def quota_denial(result, resource):
    message = result.stderr
    return (
        forbidden(result)
        and QUOTA_NAME in message
        and "exceeded quota" in message.lower()
        and f"requests.{resource}" in message
    )


def wait_for_usage(lab, expected):
    deadline = time.monotonic() + 15
    last = None
    while time.monotonic() < deadline:
        observed = lab.kubectl("get", "resourcequota", QUOTA_NAME, "-o", "json")
        quota = json.loads(observed.stdout)
        last = quota.get("status", {}).get("used", {})
        if all(last.get(f"requests.{key}") == value for key, value in expected.items()):
            return last
        time.sleep(0.5)
    return last or {}


def run(lab):
    omitted = workload("saf-0304-defaulted")
    max_candidates = {
        "cpu": workload(
            "saf-0304-max-cpu",
            requests={"cpu": "1m", "memory": "1Mi", "ephemeral-storage": "1Mi"},
            limits={"cpu": "201m", "memory": "2Mi", "ephemeral-storage": "2Mi"},
        ),
        "memory": workload(
            "saf-0304-max-memory",
            requests={"cpu": "1m", "memory": "1Mi", "ephemeral-storage": "1Mi"},
            limits={"cpu": "2m", "memory": "129Mi", "ephemeral-storage": "2Mi"},
        ),
        "ephemeral-storage": workload(
            "saf-0304-max-ephemeral",
            requests={"cpu": "1m", "memory": "1Mi", "ephemeral-storage": "1Mi"},
            limits={"cpu": "2m", "memory": "2Mi", "ephemeral-storage": "129Mi"},
        ),
    }
    quota_candidates = {
        "cpu": workload(
            "saf-0304-quota-cpu",
            requests={"cpu": "60m", "memory": "1Mi", "ephemeral-storage": "1Mi"},
            limits={"cpu": "80m", "memory": "2Mi", "ephemeral-storage": "2Mi"},
        ),
        "memory": workload(
            "saf-0304-quota-memory",
            requests={"cpu": "1m", "memory": "48Mi", "ephemeral-storage": "1Mi"},
            limits={"cpu": "2m", "memory": "64Mi", "ephemeral-storage": "2Mi"},
        ),
        "ephemeral-storage": workload(
            "saf-0304-quota-ephemeral",
            requests={"cpu": "1m", "memory": "1Mi", "ephemeral-storage": "48Mi"},
            limits={"cpu": "2m", "memory": "2Mi", "ephemeral-storage": "64Mi"},
        ),
    }

    # Red phase: the same requests are accepted before the namespace policies
    # exist. Server-side dry-run verifies admission reachability without Pods.
    red_default = lab.create(omitted, dry_run=True, allow_failure=True)
    red_default_resources = resources_of(json.loads(red_default.stdout)) if red_default.returncode == 0 else None
    lab.check("red", "Without a LimitRange, an omitted-resource Pod remains un-defaulted",
              red_default.returncode == 0 and red_default_resources == {}, red_default_resources)
    for resource, candidate in max_candidates.items():
        result = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check("red", f"Without a LimitRange, the {resource} over-maximum candidate reaches admission",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted candidate")
    for resource, candidate in quota_candidates.items():
        result = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check("red", f"Without a ResourceQuota, the {resource} aggregate-overage candidate reaches admission",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted candidate")

    lab.apply(HERE / "resources.yaml")

    defaulted = lab.create(omitted, dry_run=True)
    observed_defaults = resources_of(defaulted)
    lab.check(
        "green",
        "LimitRange admission injects the configured CPU, memory, and ephemeral-storage requests and limits",
        observed_defaults == DEFAULTS,
        observed_defaults,
    )

    # Each max probe changes just one resource; server-side dry-run ensures the
    # request reaches admission while creating no Pod or consuming quota.
    for resource, candidate in max_candidates.items():
        result = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check(
            "green",
            f"LimitRange rejects only the {resource} per-container maximum violation",
            limit_denial(result, resource),
            result.stderr.strip(),
        )

    # Persist two harmless idle Pods to create known aggregate declared-request
    # usage. Their resource use is not inferred from status.used.
    lab.create(workload("saf-0304-defaulted", requests=None, limits=None))
    ready(lab, "saf-0304-defaulted")
    lab.create(workload("saf-0304-aggregate-base", requests=BASE_REQUESTS, limits=BASE_LIMITS))
    ready(lab, "saf-0304-aggregate-base")

    expected_used = {"cpu": "50m", "memory": "24Mi", "ephemeral-storage": "24Mi"}
    used = wait_for_usage(lab, expected_used)
    lab.check(
        "positive",
        "ResourceQuota status accounts both admitted Pods' aggregate requests for CPU, memory, and ephemeral-storage",
        all(used.get(f"requests.{key}") == value for key, value in expected_used.items()),
        used,
    )

    # Each request exceeds exactly one aggregate budget while remaining well
    # under the per-container maxima and the other two quota dimensions.
    for resource, candidate in quota_candidates.items():
        result = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check(
            "green",
            f"ResourceQuota rejects the aggregate requests.{resource} overage",
            quota_denial(result, resource),
            result.stderr.strip(),
        )

    persisted = json.loads(lab.kubectl("get", "pods", "-o", "json").stdout)["items"]
    names = {item["metadata"]["name"] for item in persisted}
    expected_names = {"saf-0304-defaulted", "saf-0304-aggregate-base"}
    lab.check(
        "positive",
        "Dry-run max and quota denials persisted no candidate Pods",
        names == expected_names,
        sorted(names),
    )
