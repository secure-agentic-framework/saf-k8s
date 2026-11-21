"""Observe emptyDir filesystem types and Pod replacement lifecycle."""

from fixtures import container, pod, ready

SCOPE = (
    "Linux emptyDir backing filesystem, Pod replacement, and visibility of node swap "
    "and the tmpfs noswap option. Workload writes to other storage, crash dumps and "
    "hibernation are outside this fixture."
)

POD_NAME = "saf-0304-013-scratch"
MOUNT_PATH = "/scratch"

def empty_dir_pod(name, *, memory=False):
    volume = {"name": "scratch", "emptyDir": {}}
    if memory:
        volume["emptyDir"]["medium"] = "Memory"
    return pod(
        name,
        [container("probe", volumeMounts=[{"name": "scratch", "mountPath": MOUNT_PATH}])],
        volumes=[volume],
        securityContext={"fsGroup": 65534, "fsGroupChangePolicy": "OnRootMismatch"},
    )


def inspect_mount(lab, *, phase, expected_type, marker_action):
    # Match the exact mountpoint so evidence comes from the mounted emptyDir rather
    # than the container's root filesystem. /proc/mounts exposes the kernel fs type.
    script = r'''set -eu
line=$(awk '$2 == "/scratch" { print $0; exit }' /proc/mounts)
test -n "$line"
fs_type=$(printf '%s\n' "$line" | awk '{print $3}')
options=$(printf '%s\n' "$line" | awk '{print $4}')
case "$1" in
  write) printf '%s\n' 'saf-0304-013 synthetic marker' > /scratch/saf-0304-013-marker ;;
  check) if test -e /scratch/saf-0304-013-marker; then marker=present; else marker=absent; fi ;;
esac
printf 'fs=%s marker=%s options=%s' "$fs_type" "${marker:-written}" "$options"
'''
    observed = lab.kubectl("exec", POD_NAME, "--", "sh", "-c", script,
                           "probe", marker_action).stdout.strip()
    fields = dict(item.split("=", 1) for item in observed.split())
    fs_matches = (fields.get("fs") != "tmpfs" if expected_type == "not-tmpfs"
                  else fields.get("fs") == expected_type)
    lab.check(phase, f"mounted emptyDir is {expected_type} and marker is {marker_action}",
              fs_matches and fields.get("marker") == (
                  "written" if marker_action == "write" else "absent"
              ), observed)
    return fields


def run(lab):
    # Baseline: an unqualified emptyDir is writable, but its mount is not tmpfs.
    lab.create(empty_dir_pod(POD_NAME))
    ready(lab, POD_NAME)
    inspect_mount(lab, phase="red", expected_type="not-tmpfs", marker_action="write")

    # The mechanism under review explicitly selects the memory-backed medium.
    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--grace-period=1", "--timeout=30s")
    lab.create(empty_dir_pod(POD_NAME, memory=True))
    ready(lab, POD_NAME)
    memory = inspect_mount(lab, phase="green", expected_type="tmpfs", marker_action="write")
    swaps = lab.kubectl("exec", POD_NAME, "--", "cat", "/proc/swaps").stdout.splitlines()
    if not swaps or not swaps[0].startswith("Filename"):
        lab.block("Could not read the kernel swap inventory")
    active_swap = len(swaps) > 1
    noswap = "noswap" in memory["options"].split(",")
    lab.check("green", "Node swap is disabled or the actual tmpfs mount has noswap",
              not active_swap or noswap, {"active_swap": active_swap, "noswap": noswap})

    old_uid = lab.kubectl("get", "pod", POD_NAME, "-o", "jsonpath={.metadata.uid}").stdout.strip()
    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--grace-period=1", "--timeout=30s")
    lab.create(empty_dir_pod(POD_NAME, memory=True))
    ready(lab, POD_NAME)
    new_uid = lab.kubectl("get", "pod", POD_NAME, "-o", "jsonpath={.metadata.uid}").stdout.strip()
    lab.check("positive", "replacement Pod has the same name and a different UID",
              bool(old_uid and new_uid and old_uid != new_uid), f"old={old_uid} new={new_uid}")
    inspect_mount(lab, phase="positive", expected_type="tmpfs", marker_action="check")
