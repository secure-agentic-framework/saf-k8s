"""Exercise a narrow tenant Pod admission boundary for storage workloads."""

import json

from fixtures import BUSYBOX_IMAGE

SCOPE = (
    "Kubernetes v1.36.1 Pod Security Admission in the runner's isolated saf-test namespace. "
    "Checks strict admission of synthetic privileged and hostPath declarations by dry-run "
    "only, and a real allowed nonroot reader on the bundled local-path provisioner. Dedicated "
    "privileged storage drivers, provider hardening, risk review and real datasets require "
    "their own evidence."
)


def pod(name, *, privileged=False, host_path=False, pvc=False, readonly=True, command="sleep 3600"):
    volume = {"name": "storage"}
    mount = {"name": "storage", "mountPath": "/data", "readOnly": readonly}
    if host_path:
        volume["hostPath"] = {"path": "/var/lib/saf-test-fixture", "type": "Directory"}
    elif pvc:
        volume["persistentVolumeClaim"] = {"claimName": "synthetic-storage", "readOnly": readonly}
    else:
        volume["emptyDir"] = {}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "workload",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-ec", command],
                "volumeMounts": [mount],
                "securityContext": {
                    "allowPrivilegeEscalation": privileged,
                    "capabilities": {"drop": ["ALL"]},
                    "privileged": privileged,
                },
            }],
            "volumes": [volume],
        },
    }


def pvc():
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "synthetic-storage"},
        "spec": {
            "storageClassName": "standard",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "1Mi"}},
        },
    }


def run(lab):
    probes = (
        ("privileged", pod("privileged-probe", privileged=True), "privileged"),
        ("hostPath", pod("hostpath-probe", host_path=True), "hostPath"),
    )
    for name, candidate, reason in probes:
        baseline = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check(
            "red",
            f"Unrestricted namespace admits the synthetic {name} storage Pod",
            baseline.returncode == 0,
            {"admitted": baseline.returncode == 0, "detail": baseline.stderr.strip()},
        )

    lab.kubectl(
        "label", "namespace", "saf-test",
        "pod-security.kubernetes.io/enforce=restricted",
        "pod-security.kubernetes.io/enforce-version=v1.36",
        "--overwrite",
    )

    for name, candidate, reason in probes:
        denied = lab.create(candidate, dry_run=True, allow_failure=True)
        detail = denied.stderr.strip()
        matched = denied.returncode != 0 and "violates PodSecurity" in detail and reason in detail
        lab.check(
            "green",
            f"Restricted Pod Security admission rejects the {name} storage Pod",
            matched,
            {"denied": denied.returncode != 0, "expected_reason": reason, "detail": detail},
        )

    lab.create(pvc())
    writer = pod("isolated-pvc-writer", pvc=True, readonly=False,
                 command="printf '%s\\n' synthetic-storage-marker > /data/marker")
    lab.create(writer)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/isolated-pvc-writer",
                "--timeout=90s", timeout=100)
    reader = pod("isolated-pvc-reader", pvc=True, command=(
        "test \"$(cat /data/marker)\" = synthetic-storage-marker; "
        "if touch /data/should-not-write 2>/dev/null; then exit 3; fi; "
        "awk '$5==\"/data\" {print $6}' /proc/self/mountinfo; "
        "printf '%s\\n' synthetic-storage-marker"
    ))
    lab.create(reader)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/isolated-pvc-reader",
                "--timeout=90s", timeout=100)
    bound = json.loads(lab.kubectl("get", "pvc", "synthetic-storage", "-o", "json").stdout)
    mount, content = lab.kubectl("logs", "isolated-pvc-reader").stdout.strip().splitlines()
    lab.check(
        "positive",
        "Restricted admission allows a nonroot reader of a real bound PVC with a read-only mount",
        bound["status"]["phase"] == "Bound" and "ro" in mount.split(",") and content == "synthetic-storage-marker",
        {"claim_bound": bound["status"]["phase"] == "Bound", "read_only_mount": "ro" in mount.split(","),
         "marker_matches": content == "synthetic-storage-marker"},
    )
