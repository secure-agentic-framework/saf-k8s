"""Review emptyDir declarations, ephemeral-storage admission, and bounded IO."""
import json
import time
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).parent
POLICY_MESSAGE = (
    "disk-backed emptyDir needs a positive sizeLimit and regular and init containers need "
    "ephemeral-storage requests and limits"
)
QUOTA_NAME = "saf-0304-ephemeral-budget"
NAMESPACE_LABEL = "saf-k8s.example/scratch-budget"
SCOPE = (
    "One isolated namespace on the lab's pinned Kubernetes v1.36.1 kind cluster. "
    "Paired server-side dry-runs compare absent emptyDir sizeLimit and absent regular-container "
    "or init-container ephemeral-storage declarations before and after a case-owned ValidatingAdmissionPolicy. "
    "ResourceQuota admission is checked for aggregate declared requests and limits. One tiny "
    "marker is read below its bound. A paired disk-backed emptyDir comparison writes 1 MiB "
    "below and 3 MiB above a 2 MiB volume sizeLimit while each Pod has a 16 MiB aggregate "
    "container ephemeral-storage limit, isolating the volume-specific kubelet eviction. "
    "Native kubelet volume usage and node filesystem capacity are sampled on the disposable node."
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
        automountServiceAccountToken=False, terminationGracePeriodSeconds=1,
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


def node_disk_pressure(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout).get("items", [])
    if len(nodes) != 1:
        return None
    conditions = {condition["type"]: condition["status"]
                  for condition in nodes[0]["status"].get("conditions", [])}
    return conditions.get("DiskPressure")



def read_kubelet_storage(lab, pod_name):
    listing = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    node, = listing["items"]
    path = f"/api/v1/nodes/{node['metadata']['name']}/proxy/stats/summary"
    for _ in range(40):
        summary = json.loads(lab.kubectl("get", "--raw", path).stdout)
        filesystem = summary["node"].get("fs", {})
        for stats in summary.get("pods", []):
            ref = stats["podRef"]
            if ref["namespace"] == "saf-test" and ref["name"] == pod_name:
                for volume in stats.get("volume", []):
                    if volume["name"] == "scratch" and volume.get("usedBytes", 0) >= 1024 * 1024:
                        return filesystem, volume
        time.sleep(2)
    lab.block("Kubelet did not report the fixture's disk-backed scratch volume")


def pod_status(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout).get("status", {})


def wait_for_eviction(lab, name, timeout=120):
    deadline = time.monotonic() + timeout
    observed = {}
    while time.monotonic() < deadline:
        observed = pod_status(lab, name)
        if observed.get("phase") == "Failed" or observed.get("reason") == "Evicted":
            return observed
        time.sleep(2)
    return observed


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{NAMESPACE_LABEL}=required", "--overwrite")

    missing_size = scratch_pod("saf-0304-012-missing-size", size_limit=None)
    missing_resources = scratch_pod(
        "saf-0304-012-missing-resources", request=None, limit=None,
    )
    missing_init = scratch_pod("saf-0304-012-missing-init-resources")
    missing_init["spec"]["initContainers"] = [
        container("initializer", command=["sh", "-c", "true"])
    ]
    memory_scratch = scratch_pod("saf-0304-012-memory-backed", size_limit=None, request=None, limit=None)
    memory_scratch["spec"]["volumes"][0]["emptyDir"] = {"medium": "Memory"}
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
        "missing_init": server_create(lab, missing_init),
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
        "missing_init": server_create(lab, missing_init),
        "valid": server_create(lab, scratch_pod("saf-0304-012-valid")),
        "memory_scratch": server_create(lab, memory_scratch),
        "request_overage": server_create(lab, request_overage),
        "limit_overage": server_create(lab, limit_overage),
    }
    lab.check(
        "green", "The policy rejects missing scratch bounds and preserves valid, over-budget declarations for quota evaluation",
        policy_denial(green_policy["missing_size"])
        and policy_denial(green_policy["missing_resources"])
        and policy_denial(green_policy["missing_init"])
        and admitted(green_policy["memory_scratch"])
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


    # The aggregate container limit (16 MiB) is intentionally above both writes;
    # only the 2 MiB emptyDir sizeLimit is crossed by the second Pod.
    pressure_before = node_disk_pressure(lab)
    comparison = {"request": "1Mi", "limit": "16Mi", "size_limit": "2Mi"}
    below_name, above_name = "saf-0304-012-volume-below", "saf-0304-012-volume-above"
    below_command = (
        "dd if=/dev/zero of=/scratch/probe bs=1M count=1 2>/dev/null; "
        "test \"$(wc -c < /scratch/probe)\" -eq 1048576; exec sleep 3600"
    )
    above_command = (
        "dd if=/dev/zero of=/scratch/probe bs=1M count=3 2>/dev/null; "
        "test \"$(wc -c < /scratch/probe)\" -eq 3145728; exec sleep 3600"
    )
    below = scratch_pod(below_name, size_limit=comparison["size_limit"],
                        request=comparison["request"], limit=comparison["limit"], command=below_command)
    lab.create(below)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{below_name}", "--timeout=45s", timeout=55)
    below_write = lab.kubectl("exec", below_name, "-c", "probe", "--", "sh", "-ec",
                              "test \"$(wc -c < /scratch/probe)\" -eq 1048576", allow_failure=True)
    filesystem, volume = read_kubelet_storage(lab, below_name)
    observed_capacity = 0 < filesystem.get("availableBytes", 0) <= filesystem.get("capacityBytes", 0)
    below_volume_observed = 1024 * 1024 <= volume["usedBytes"] < 2 * 1024 * 1024
    lab.check(
        "positive", "Kubelet reports positive node storage headroom and measures the named scratch volume",
        observed_capacity and below_volume_observed,
        {"node_capacity_observed": observed_capacity, "scratch_usage_below_limit": below_volume_observed},
    )
    below_state = pod_status(lab, below_name)
    below_ok = (below_write.returncode == 0 and below_state.get("phase") == "Running"
                and below_state.get("reason") != "Evicted")
    lab.check("positive", "The same-case 1 MiB control remains running below its 2 MiB emptyDir sizeLimit",
              below_ok, {"phase": below_state.get("phase"), "reason": below_state.get("reason"),
                         "written_bytes": 1048576, **comparison})
    lab.kubectl("delete", "pod", below_name, "--wait=true", "--timeout=25s", timeout=35)

    above = scratch_pod(above_name, size_limit=comparison["size_limit"],
                        request=comparison["request"], limit=comparison["limit"], command=above_command)
    lab.create(above)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{above_name}", "--timeout=45s", timeout=55)
    above_write = lab.kubectl("exec", above_name, "-c", "probe", "--", "sh", "-ec",
                              "test \"$(wc -c < /scratch/probe)\" -eq 3145728", allow_failure=True)
    above_state = wait_for_eviction(lab, above_name)
    message = above_state.get("message", "")
    # Kubernetes' native Pod eviction reason plus its volume-name/size message
    # distinguishes this from aggregate container limits and node-pressure eviction.
    exact_volume_eviction = (
        above_state.get("reason") == "Evicted"
        and "EmptyDir volume" in message and "scratch" in message and "2Mi" in message
        and "total limit of containers" not in message
        and "node was low on resource" not in message.lower()
    )
    volume_message = 'Usage of EmptyDir volume "scratch" exceeds the limit "2Mi".'
    exact_events = []
    for _ in range(12):
        events = json.loads(lab.kubectl("get", "events", "--field-selector",
                                       f"involvedObject.name={above_name}", "-o", "json").stdout).get("items", [])
        exact_events = [event for event in events if event.get("reason") == "Evicted"
                        and volume_message in event.get("message", "")]
        if exact_events:
            break
        time.sleep(1)
    (lab.evidence / "scratch-volume-accounting.json").write_text(json.dumps({
        "node_filesystem": {key: filesystem[key] for key in ("capacityBytes", "availableBytes")},
        "below_volume": {"name": volume["name"], "used_bytes": volume["usedBytes"]},
        "above_pod_reason": above_state.get("reason"),
        "above_pod_message": message,
        "volume_events": [event["message"] for event in exact_events],
    }, indent=2, sort_keys=True) + "\n")
    pressure_after = node_disk_pressure(lab)
    lab.check("red", "A 3 MiB write completes above the 2 MiB volume sizeLimit",
              above_write.returncode == 0,
              {"written_bytes": 3145728, "emptyDir_sizeLimit": comparison["size_limit"],
               "aggregate_ephemeral_storage_limit": comparison["limit"]})
    lab.check("green", "Kubelet reports the exact emptyDir volume-size eviction without node DiskPressure",
              exact_volume_eviction and volume_message in message and bool(exact_events)
              and pressure_before == pressure_after == "False",
              {"pod_reason": above_state.get("reason"), "pod_message": message,
               "matching_volume_event": bool(exact_events),
               "aggregate_ephemeral_storage_limit": comparison["limit"],
               "emptyDir_sizeLimit": comparison["size_limit"],
               "node_disk_pressure_before_and_after": [pressure_before, pressure_after]})
