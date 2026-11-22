"""Review emptyDir declarations, ephemeral-storage admission, and bounded IO."""
import json
import time
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).parent
POLICY_MESSAGE = (
    "emptyDir volumes need a positive sizeLimit and regular containers need "
    "ephemeral-storage requests and limits"
)
QUOTA_NAME = "saf-0304-ephemeral-budget"
NAMESPACE_LABEL = "saf-k8s.example/scratch-budget"
SCOPE = (
    "One isolated namespace on the lab's pinned Kubernetes v1.36.1 kind cluster. "
    "Paired server-side dry-runs compare absent emptyDir sizeLimit and absent regular-container "
    "ephemeral-storage declarations before and after a case-owned ValidatingAdmissionPolicy. "
    "ResourceQuota admission is checked for aggregate declared requests and limits. One tiny "
    "marker is read below its bound. A second workload writes only 128 KiB against a 64 KiB "
    "disk-backed emptyDir bound to observe kubelet eviction on the test filesystem. "
    "Production filesystem and training workload behavior require deployment evidence."
)


def scratch_pod(name, *, size_limit="1Mi", request="4Mi", limit="8Mi", command=None):
    empty_dir = {} if size_limit is None else {"sizeLimit": size_limit}
    resources = {}
    if request is not None:
        resources["requests"] = {"ephemeral-storage": request}
    if limit is not None:
        resources["limits"] = {"ephemeral-storage": limit}
    args = {}
    if resources:
        args["resources"] = resources
    if command is not None:
        args["command"] = ["sh", "-c", command]
    return pod(
        name,
        [container("probe", volumeMounts=[{"name": "scratch", "mountPath": "/scratch"}], **args)],
        automountServiceAccountToken=False,
        volumes=[{"name": "scratch", "emptyDir": empty_dir}],
    )


def server_create(lab, resource):
    return lab.create(resource, dry_run=True, allow_failure=True)


def admitted(result):
    return result.returncode == 0


def policy_denial(result):
    return result.returncode != 0 and POLICY_MESSAGE in result.stderr


def quota_denial(result, resource):
    return (
        result.returncode != 0
        and "(Forbidden)" in result.stderr
        and QUOTA_NAME in result.stderr
        and "exceeded quota" in result.stderr.lower()
        and f"{resource}.ephemeral-storage" in result.stderr
    )


def wait_for_quota(lab):
    deadline = time.monotonic() + 20
    observed = {}
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "resourcequota", QUOTA_NAME, "-o", "json")
        observed = json.loads(result.stdout).get("status", {}).get("used", {})
        if (observed.get("requests.ephemeral-storage") == "4Mi"
                and observed.get("limits.ephemeral-storage") == "8Mi"):
            return observed
        time.sleep(0.5)
    return observed


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{NAMESPACE_LABEL}=required", "--overwrite")

    missing_size = scratch_pod("saf-0304-012-missing-size", size_limit=None)
    missing_resources = scratch_pod(
        "saf-0304-012-missing-resources", request=None, limit=None,
    )
    request_overage = scratch_pod(
        "saf-0304-012-request-overage", request="16Mi", limit="16Mi",
    )
    limit_overage = scratch_pod(
        "saf-0304-012-limit-overage", request="4Mi", limit="32Mi",
    )

    # Red: the same invalid or over-budget declarations reach the API before
    # either case-owned admission mechanism is installed.
    red = {
        "missing_size": server_create(lab, missing_size),
        "missing_resources": server_create(lab, missing_resources),
        "request_overage": server_create(lab, request_overage),
        "limit_overage": server_create(lab, limit_overage),
    }
    lab.check(
        "red", "Without case policy or quota, the API admits each bounded candidate",
        all(admitted(result) for result in red.values()),
        {name: {"admitted": admitted(result), "detail": result.stderr.strip()}
         for name, result in red.items()},
    )

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 20
    missing_size_result = server_create(lab, missing_size)
    while not policy_denial(missing_size_result) and time.monotonic() < deadline:
        time.sleep(0.5)
        missing_size_result = server_create(lab, missing_size)
    green_policy = {
        "missing_size": missing_size_result,
        "missing_resources": server_create(lab, missing_resources),
        "valid": server_create(lab, scratch_pod("saf-0304-012-valid")),
        "request_overage": server_create(lab, request_overage),
        "limit_overage": server_create(lab, limit_overage),
    }
    lab.check(
        "green", "The policy rejects missing scratch bounds and preserves valid, over-budget declarations for quota evaluation",
        policy_denial(green_policy["missing_size"])
        and policy_denial(green_policy["missing_resources"])
        and all(admitted(green_policy[name]) for name in
                ("valid", "request_overage", "limit_overage")),
        {name: {"admitted": admitted(result), "policy_denied": policy_denial(result),
                "detail": result.stderr.strip()}
         for name, result in green_policy.items()},
    )

    tiny_marker = "printf 'saf-0304-012 marker\\n' > /scratch/marker; test \"$(wc -c < /scratch/marker)\" -le 64; exec sleep 3600"
    live = scratch_pod("saf-0304-012-bounded-positive", command=tiny_marker)
    lab.create(live)
    lab.kubectl("wait", "--for=condition=Ready",
                 "pod/saf-0304-012-bounded-positive", "--timeout=60s", timeout=70)
    output = lab.kubectl("exec", "saf-0304-012-bounded-positive", "-c", "probe",
                         "--", "cat", "/scratch/marker").stdout
    lab.check(
        "positive", "A tiny marker write and read succeeds below the declared volume and container bounds",
        output == "saf-0304-012 marker\n", output,
    )

    lab.apply(HERE / "quota.yaml")
    usage = wait_for_quota(lab)
    # These exact Pod specs were admitted before the quota existed. Each changes
    # just one aggregate declared-storage dimension and uses server dry-run.
    request_result = server_create(lab, request_overage)
    limit_result = server_create(lab, limit_overage)
    lab.check(
        "green", "ResourceQuota denies aggregate requests and limits by their exact declared-storage keys",
        quota_denial(request_result, "requests") and quota_denial(limit_result, "limits"),
        {"requests": request_result.stderr.strip(), "limits": limit_result.stderr.strip()},
    )
    lab.check(
        "positive", "Quota status records only the live Pod's declared request and limit",
        usage.get("requests.ephemeral-storage") == "4Mi"
        and usage.get("limits.ephemeral-storage") == "8Mi",
        usage,
    )


    over_volume = "saf-0304-012-volume-comparison"
    lab.create(scratch_pod(over_volume, size_limit="64Ki"))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{over_volume}",
                "--timeout=45s", timeout=55)
    write = lab.kubectl("exec", over_volume, "-c", "probe", "--", "sh", "-ec",
                        "dd if=/dev/zero of=/scratch/probe bs=1024 count=128 2>/dev/null; "
                        "test \"$(wc -c < /scratch/probe)\" -eq 131072")
    lab.check("red", "A disk-backed emptyDir write succeeds above the declared sizeLimit",
              write.returncode == 0, {"fixed_bytes_written": 131072, "volume_limit_bytes": 65536})
    deadline = time.monotonic() + 95
    evicted_for_volume = False
    while time.monotonic() < deadline:
        pod_status = json.loads(lab.kubectl("get", "pod", over_volume, "-o", "json").stdout)["status"]
        if pod_status.get("phase") == "Failed":
            message = pod_status.get("message", "")
            evicted_for_volume = (pod_status.get("reason") == "Evicted"
                                  and "EmptyDir volume" in message
                                  and "scratch" in message and "64Ki" in message)
            break
        time.sleep(2)
    lab.check("green", "The kubelet evicts the tiny over-limit Pod for the exact scratch volume",
              evicted_for_volume, {"volume_eviction_observed": evicted_for_volume})
