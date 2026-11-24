"""Exercise bounded kubelet local ephemeral-storage accounting and eviction."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
NS = "saf-lab-0304-010-ephemeral-storage"
REQUESTS = {"cpu": "10m", "memory": "16Mi", "ephemeral-storage": "1Mi"}
BASE_LIMITS = {"cpu": "100m", "memory": "32Mi", "ephemeral-storage": "8Mi"}
STORAGE_LIMIT = "4Mi"
WRITE_LIMIT_MIB = 6
CONTROL_SETTLE_SECONDS = 70
MONITOR_TIMEOUT = 180


def workload(name, *, size_mib, storage_limit):
    """Build both control and eviction workloads from the same Pod template."""
    limits = {**BASE_LIMITS, "ephemeral-storage": storage_limit}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NS, "labels": {"saf.example.com/probe": "ephemeral-storage"}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "containers": [{
                "name": "writer",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-c", f"dd if=/dev/zero of=/scratch/payload bs=1M count={size_mib} && echo storage-write-complete && sleep 3600"],
                "resources": {"requests": REQUESTS, "limits": limits},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "scratch", "mountPath": "/scratch"}],
            }],
            "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "8Mi"}}],
        },
    }


def json_resource(lab, *arguments):
    return json.loads(lab.kubectl(*arguments, "-o", "json").stdout)


def node_disk_pressure(lab):
    nodes = json_resource(lab, "get", "nodes")["items"]
    if len(nodes) != 1:
        return None
    conditions = {c["type"]: c["status"] for c in nodes[0]["status"].get("conditions", [])}
    return conditions.get("DiskPressure")


def pod_state(lab, name):
    return json_resource(lab, "-n", NS, "get", "pod", name)


def wait_for(lab, name, predicate, timeout):
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = pod_state(lab, name)
        if predicate(observed):
            return observed
        time.sleep(2)
    return observed


def create(lab, obj):
    return lab.kubectl("-n", NS, "create", "-f", "-", payload=json.dumps(obj), allow_failure=True)


def run(lab):
    lab.kubectl("create", "namespace", NS)
    pressure_before = node_disk_pressure(lab)
    lab.check("positive", "Kind starts without Node DiskPressure", pressure_before == "False",
              {"disk_pressure": pressure_before})

    below_name, above_name = "storage-below-limit", "storage-above-limit"
    below = workload(below_name, size_mib=1, storage_limit=STORAGE_LIMIT)
    above = workload(above_name, size_mib=WRITE_LIMIT_MIB, storage_limit=STORAGE_LIMIT)
    below_result = create(lab, below)
    lab.check("positive", "The below-limit workload is accepted", below_result.returncode == 0,
              {"created": below_result.returncode == 0})

    time.sleep(CONTROL_SETTLE_SECONDS)  # Allow periodic kubelet storage scans to account for the control Pod.
    below_state = pod_state(lab, below_name)
    below_log = lab.kubectl("-n", NS, "logs", below_name, allow_failure=True)
    below_written = below_log.returncode == 0 and "storage-write-complete" in below_log.stdout
    below_ok = (below_written and below_state["status"].get("phase") == "Running"
                and below_state["status"].get("reason") != "Evicted")
    lab.check("positive", "The below-limit write stays running without eviction",
              below_ok, {"phase": below_state["status"].get("phase"),
                         "reason": below_state["status"].get("reason"), "write_completed": below_written, "written_mib": 1})
    lab.kubectl("-n", NS, "delete", "pod", below_name, "--wait=true", "--timeout=25s", timeout=35)
    above_result = create(lab, above)
    lab.check("positive", "The above-limit workload is accepted", above_result.returncode == 0,
              {"created": above_result.returncode == 0})

    above_state = wait_for(
        lab, above_name,
        lambda pod: pod["status"].get("phase") == "Failed" or pod["status"].get("reason") == "Evicted",
        MONITOR_TIMEOUT,
    )
    message = above_state["status"].get("message", "")
    limit_message = f"Pod ephemeral local storage usage exceeds the total limit of containers {STORAGE_LIMIT}."
    own_limit_eviction = (
        above_state["status"].get("reason") == "Evicted"
        and limit_message in message
        and "node was low on resource" not in message.lower()
    )
    pressure_after = node_disk_pressure(lab)
    matching_events = []
    for _ in range(12):
        events = json_resource(lab, "-n", NS, "get", "events", "--field-selector",
                               f"involvedObject.name={above_name}")["items"]
        matching_events = [event for event in events if event.get("reason") == "Evicted"
                           and limit_message in event.get("message", "")]
        if matching_events:
            break
        time.sleep(1)
    evidence = {
        "result": "kubelet-pod-local-ephemeral-storage-limit-exceeded" if own_limit_eviction else "unmatched",
        "pod": above_name,
        "pod_reason": above_state["status"].get("reason"),
        "pod_message": message,
        "container_statuses": above_state["status"].get("containerStatuses", []),
        "event_messages": [event.get("message", "") for event in matching_events],
        "write_mib_max": WRITE_LIMIT_MIB,
        "ephemeral_storage_request": REQUESTS["ephemeral-storage"],
        "ephemeral_storage_limit": STORAGE_LIMIT,
        "node_disk_pressure": pressure_after,
    }
    (lab.evidence / "local-ephemeral-storage-eviction.json").write_text(json.dumps(evidence, indent=2) + "\n")
    lab.check("green", "Kubelet evicts the above-limit Pod for its own local ephemeral-storage limit",
              own_limit_eviction and bool(matching_events) and pressure_before == pressure_after == "False",
              {"matching_kubelet_pod_limit_eviction": own_limit_eviction,
               "matching_event_recorded": bool(matching_events),
               "node_disk_pressure_before_and_after": [pressure_before, pressure_after]})
