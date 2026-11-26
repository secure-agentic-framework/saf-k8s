"""Case-owned Pod user-namespace continuity witness.

Call create_and_snapshot() before the reviewed kubeadm upgrade sequence, then
snapshot() after the control plane and kubelet reach the target version. Call
check_preserved() to add one independent positive check. This module performs
only normal Pod create/get/wait/exec/delete operations through the lab's
case-scoped kubectl wrapper. It does not alter node or runtime configuration.
"""

import json
import time


CONTROL_ID = "SAF-K8S-0104-013"
POD_NAME = "saf-0104-013-userns-canary"
CONTAINER_NAME = "userns-canary"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
RUN_UID = 65534
RUN_GID = 65534
WAIT_SECONDS = 90

_OBSERVE_PROGRAM = (
    "import json,os; "
    "print(json.dumps({'euid':os.geteuid(),'egid':os.getegid(),"
    "'uid_map':open('/proc/self/uid_map').read(),"
    "'gid_map':open('/proc/self/gid_map').read(),"
    "'user_ns':os.readlink('/proc/self/ns/user')}))"
)

_READY_PROGRAM = (
    "import os; "
    f"assert os.geteuid()=={RUN_UID} and os.getegid()=={RUN_GID}; "
    "assert open('/proc/self/uid_map').read().strip(); "
    "assert open('/proc/self/gid_map').read().strip()"
)


def pod_manifest():
    """Return one inert, restricted, non-root Pod using the stable hostUsers field."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": POD_NAME,
            "namespace": "saf-test",
            "labels": {
                "saf-lab.example/control": CONTROL_ID,
                "saf-lab.example/fixture": "userns-continuity",
            },
        },
        "spec": {
            "hostUsers": False,
            "restartPolicy": "Always",
            "terminationGracePeriodSeconds": 2,
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": RUN_UID,
                "runAsGroup": RUN_GID,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": CONTAINER_NAME,
                "image": IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(86400)"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": "5m", "memory": "16Mi"},
                    "limits": {"cpu": "100m", "memory": "64Mi"},
                },
                "readinessProbe": {
                    "exec": {"command": ["python", "-B", "-c", _READY_PROGRAM]},
                    "periodSeconds": 2,
                    "timeoutSeconds": 2,
                    "failureThreshold": 3,
                },
            }],
        },
    }


def _map_rows(text, container_id):
    """Parse /proc/*_map and prove the requested container ID maps off-host."""
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise ValueError("malformed namespace ID map")
        inside, outside, count = (int(value, 10) for value in fields)
        if inside < 0 or outside < 0 or count <= 0:
            raise ValueError("invalid namespace ID map range")
        rows.append((inside, outside, count))
    if not rows:
        raise ValueError("empty namespace ID map")
    matches = [row for row in rows if row[0] <= container_id < row[0] + row[2]]
    if len(matches) != 1:
        raise ValueError("container ID is not covered by exactly one namespace mapping")
    inside, outside, _count = matches[0]
    host_id = outside + container_id - inside
    if host_id <= 65535 or host_id == container_id:
        raise ValueError("default user-namespace mapping did not place the ID outside host IDs")
    return tuple(rows), host_id


def _ready(pod):
    status = pod.get("status", {})
    ready_condition = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in status.get("conditions", [])
    )
    statuses = status.get("containerStatuses", [])
    container = [row for row in statuses if row.get("name") == CONTAINER_NAME]
    return (
        status.get("phase") == "Running"
        and ready_condition
        and len(container) == 1
        and container[0].get("ready") is True
    )


def snapshot(lab, *, stage, expected_uid=None):
    """Wait boundedly for Ready and return API identity plus observed UID/GID maps."""
    deadline = time.monotonic() + WAIT_SECONDS
    last_error = "Pod not yet Ready"
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "pod", POD_NAME, "-o", "json",
                               allow_failure=True, timeout=12)
        if response.returncode == 0:
            try:
                pod = json.loads(response.stdout)
            except json.JSONDecodeError:
                last_error = "Pod API response was not JSON"
            else:
                metadata = pod.get("metadata", {})
                pod_uid = metadata.get("uid")
                if not pod_uid:
                    last_error = "Pod API response lacked metadata.uid"
                elif expected_uid is not None and pod_uid != expected_uid:
                    lab.block("User-namespace canary Pod UID changed across the upgrade")
                elif (pod.get("spec", {}).get("hostUsers") is not False
                      or metadata.get("namespace") != "saf-test"):
                    lab.block("Canary API readback no longer shows the case-owned hostUsers:false Pod")
                elif _ready(pod):
                    observed = lab.kubectl(
                        "exec", POD_NAME, "-c", CONTAINER_NAME, "--",
                        "python", "-B", "-c", _OBSERVE_PROGRAM,
                        allow_failure=True, timeout=12,
                    )
                    if observed.returncode == 0:
                        try:
                            process = json.loads(observed.stdout)
                            uid_rows, host_uid = _map_rows(process["uid_map"], RUN_UID)
                            gid_rows, host_gid = _map_rows(process["gid_map"], RUN_GID)
                        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                            lab.block(f"Invalid user-namespace identity evidence: {exc}")
                        if process.get("euid") != RUN_UID or process.get("egid") != RUN_GID:
                            lab.block("Canary process did not run as the declared non-root UID/GID")
                        statuses = pod.get("status", {}).get("containerStatuses", [])
                        container, = [row for row in statuses if row.get("name") == CONTAINER_NAME]
                        return {
                            "stage": stage,
                            "pod_uid": pod_uid,
                            "namespace": metadata["namespace"],
                            "node_name": pod.get("spec", {}).get("nodeName"),
                            "host_users": pod["spec"]["hostUsers"],
                            "phase": pod["status"]["phase"],
                            "ready": True,
                            "container_id": container.get("containerID"),
                            "restart_count": container.get("restartCount"),
                            "euid": process["euid"],
                            "egid": process["egid"],
                            "uid_map": uid_rows,
                            "gid_map": gid_rows,
                            "mapped_host_uid": host_uid,
                            "mapped_host_gid": host_gid,
                            "user_namespace_inode": process.get("user_ns"),
                        }
                    last_error = "Pod exec identity read raced with container restart"
        else:
            last_error = "Pod API read failed while waiting for readiness"
        time.sleep(1)
    lab.block(f"User-namespace canary did not produce bounded Ready/mapping evidence: {last_error}")


def create_and_snapshot(lab):
    """Create the owned canary and return its first stable mapping snapshot."""
    created = lab.create(pod_manifest())
    created_uid = created.get("metadata", {}).get("uid")
    if not created_uid:
        lab.block("Created user-namespace canary lacks an API-assigned Pod UID")
    return snapshot(lab, stage="pre-upgrade", expected_uid=created_uid)


def check_preserved(lab, before, after):
    """Add one check proving same Pod identity and same effective ID mappings."""
    comparisons = {
        "pod_uid_unchanged": before["pod_uid"] == after["pod_uid"],
        "host_users_false_before_and_after": (
            before["host_users"] is False and after["host_users"] is False
        ),
        "uid_map_unchanged": before["uid_map"] == after["uid_map"],
        "gid_map_unchanged": before["gid_map"] == after["gid_map"],
        "mapped_host_ids_unchanged": (
            before["mapped_host_uid"] == after["mapped_host_uid"]
            and before["mapped_host_gid"] == after["mapped_host_gid"]
        ),
        "nonroot_identity_unchanged": (
            before["euid"] == after["euid"] == RUN_UID
            and before["egid"] == after["egid"] == RUN_GID
        ),
        "same_node": before["node_name"] == after["node_name"],
        "ready_after_upgrade": after["ready"] is True,
    }
    lab.check(
        "positive",
        "The same hostUsers:false Pod remains Ready with its non-root UID/GID mapping across the upgrade",
        all(comparisons.values()),
        {"comparisons": comparisons, "before": before, "after": after,
         "user_namespace_inode_compared": False},
    )
    return comparisons
