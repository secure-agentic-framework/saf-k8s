"""Compare the host UID mapping for vanilla and Pod user-namespace workloads."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE, pod

SCOPE = (
    "Local kind with its pinned Kubernetes 1.36.1 node image and containerd CRI; "
    "compares /proc/self/uid_map for a default Pod and a Pod explicitly setting "
    "hostUsers: false. Establishes kernel UID mapping and basic BusyBox operation "
    "only when the host kernel and runtime support Pod user namespaces. Does not "
    "establish escape resistance, host filesystem isolation, or production support."
)
NAMESPACE = "saf-test"
UID_MAP = "/proc/self/uid_map"


def workload(name, userns=False):
    spec = {"hostUsers": False} if userns else {}
    return pod(name, [{
        "name": "probe", "image": BUSYBOX_IMAGE,
        "command": ["sh", "-c", "while :; do sleep 3600; done"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsUser": 0, "runAsGroup": 0,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], **spec)


def uid_map(lab, pod_name):
    return lab.kubectl("exec", pod_name, "-c", "probe", "--", "cat", UID_MAP).stdout.strip()


def parse_uid_map(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdecimal() for field in fields):
            raise ValueError(f"Unexpected uid_map row: {line!r}")
        rows.append(tuple(map(int, fields)))
    return rows


def run(lab):
    case_dir = Path(__file__).parent
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/require-pod-userns=enabled")
    guard = workload("admission-guard-probe")
    before = lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                         payload=json.dumps(guard), allow_failure=True)
    lab.check("red", "A workload omitting hostUsers is admitted before the guard",
              before.returncode == 0, before.stderr.strip() or "server dry-run admitted")

    vanilla = workload("vanilla")
    lab.create(vanilla)
    lab.kubectl("wait", "--for=condition=Ready", "pod/vanilla", "--timeout=95s", timeout=105)
    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        rejected = lab.create(guard, dry_run=True, allow_failure=True)
        denied = (rejected.returncode != 0 and "(Forbidden)" in rejected.stderr
                  and "hostUsers must be false" in rejected.stderr)
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The namespace guard rejects workloads without hostUsers false",
              denied, rejected.stderr.strip() or "unexpected admission success")
    lab.create(workload("userns", True))
    lab.kubectl("wait", "--for=condition=Ready", "pod/userns", "--timeout=95s", timeout=105)
    baseline = parse_uid_map(uid_map(lab, "vanilla"))
    isolated = parse_uid_map(uid_map(lab, "userns"))
    # A normal host user namespace has an identity mapping. A userns Pod maps
    # container UID zero to a nonzero host UID, over a nontrivial range.
    lab.check("red", "Vanilla container UID zero maps to host UID zero",
              any(start == 0 and host == 0 for start, host, size in baseline), baseline)
    mapped = any(start == 0 and host != 0 and size > 1 for start, host, size in isolated)
    lab.check("green", "Pod user namespace maps container UID zero to an unprivileged host range",
              mapped, isolated)
    for pod_name in ("vanilla", "userns"):
        result = lab.kubectl("exec", pod_name, "-c", "probe", "--", "sh", "-c",
                             "test \"$(id -u)\" = 0 && printf 'busybox-ok\\n'").stdout.strip()
        lab.check("positive", f"Benign BusyBox command works in {pod_name}",
                  result == "busybox-ok", result)
