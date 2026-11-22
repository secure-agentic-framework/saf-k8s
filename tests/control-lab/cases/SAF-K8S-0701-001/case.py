"""Compare PVC access mode with the actual mode of authorized mounts."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready


CLAIM = "saf-rwo-workspace"
MODE = "ReadWriteOnce"
MARKER = "/workspace/sample.txt"
SCOPE = (
    "One kind v1.36.1 node using its default cluster-owned local-path provisioner. "
    "Two administrator-authorized nonroot Pods on the same node use one ReadWriteOnce "
    "PVC allowed by the scoped claim policy. The second Pod modifies the inert marker through a writable mount and its "
    "other container observes read-only mount enforcement on the same claim. "
    "CSI ReadWriteOncePod, other backends and filesystem authorization require "
    "independent evidence."
)


def fixture_container(name, *, read_only=False):
    return container(name, volumeMounts=[{
        "name": "fixture", "mountPath": "/workspace", "readOnly": read_only,
    }])


def workload(lab, name, containers):
    lab.create(pod(name, containers, automountServiceAccountToken=False, volumes=[{
        "name": "fixture", "persistentVolumeClaim": {"claimName": CLAIM},
    }]))
    ready(lab, name)
    return lab.kubectl("get", "pod", name, "-o", "jsonpath={.spec.nodeName}").stdout.strip()


def claim_spec(name, mode):
    return {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name},
        "spec": {"storageClassName": "standard", "accessModes": [mode],
                 "resources": {"requests": {"storage": "16Mi"}}},
    }


def dry_run_claim(lab, resource):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", payload=json.dumps(resource),
                       allow_failure=True)


def check_claim_policy(lab):
    lab.kubectl("label", "namespace", "saf-test", "saf-k8s.example/fixture-storage-mode=approved")
    invalid = claim_spec("unapproved-mode", "ReadWriteMany")
    before = dry_run_claim(lab, invalid)
    lab.check("red", "Before policy, the API admits a dry-run claim declaring an unapproved access mode",
              before.returncode == 0, {"dry_run_admitted": before.returncode == 0})
    lab.apply(Path(__file__).with_name("approved-claim-modes.yaml"))
    deadline = time.monotonic() + 20
    while True:
        after = dry_run_claim(lab, invalid)
        denied = (after.returncode != 0 and "(Forbidden)" in after.stderr
                  and "ValidatingAdmissionPolicy 'saf-k8s-0701-001-approved-mode'" in after.stderr
                  and "fixture workspace claims require standard ReadWriteOnce storage" in after.stderr)
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The same unapproved claim declaration is denied by the enrolled PVC policy",
              denied, {"denied_by_expected_policy": denied})


def run(lab):
    provisioner = lab.kubectl("get", "storageclass", "standard",
                              "-o", "jsonpath={.provisioner}").stdout.strip()
    if provisioner != "rancher.io/local-path":
        lab.block(f"Expected the pinned kind local-path StorageClass, got {provisioner!r}")
    check_claim_policy(lab)
    lab.create(claim_spec(CLAIM, MODE))

    first_node = workload(lab, "writer", [fixture_container("first")])
    lab.kubectl("exec", "writer", "-c", "first", "--", "sh", "-ec",
                f"printf '%s\\n' first-owner > {MARKER}")
    second_node = workload(lab, "other-owner",
                           [fixture_container("writable"), fixture_container("readonly", read_only=True)])
    claim = json.loads(lab.kubectl("get", "pvc", CLAIM, "-o", "json").stdout)
    volume = json.loads(lab.kubectl("get", "pv", claim["spec"]["volumeName"], "-o", "json").stdout)
    observed = {"provisioner": provisioner, "claim_access_modes": claim["spec"]["accessModes"],
                "volume_access_modes": volume["spec"]["accessModes"],
                "claim_bound": claim["status"]["phase"] == "Bound",
                "same_node": bool(first_node) and first_node == second_node}
    lab.check("positive", "Two running Pods on one node mount the exact bound ReadWriteOnce fixture",
              observed["claim_bound"] and observed["same_node"]
              and observed["claim_access_modes"] == [MODE] and observed["volume_access_modes"] == [MODE],
              observed)

    before = lab.kubectl("exec", "other-owner", "-c", "writable", "--", "cat", MARKER).stdout.strip()
    lab.kubectl("exec", "other-owner", "-c", "writable", "--", "sh", "-ec",
                f"printf '%s\\n' second-owner > {MARKER}")
    after = lab.kubectl("exec", "writer", "-c", "first", "--", "cat", MARKER).stdout.strip()
    lab.check("red", "ReadWriteOnce does not stop the second authorized Pod on the same node from writing",
              before == "first-owner" and after == "second-owner",
              {"second_owner_read": before, "first_owner_read_after_write": after})

    read = lab.kubectl("exec", "other-owner", "-c", "readonly", "--", "cat", MARKER).stdout.strip()
    options = lab.kubectl("exec", "other-owner", "-c", "readonly", "--",
                          "awk", '$5=="/workspace"{print $6}', "/proc/self/mountinfo").stdout.strip()
    failed = lab.kubectl("exec", "other-owner", "-c", "readonly", "--",
                         "touch", "/workspace/fixture-rejected", allow_failure=True)
    ro = "ro" in options.split(",")
    denied = failed.returncode != 0 and "read-only file system" in failed.stderr.lower()
    lab.check("green", "The explicit read-only container mount denies writes and still reads the shared marker",
              ro and denied and read == "second-owner",
              {"mount_readonly": ro, "write_denied_by_readonly_mount": denied, "marker": read})
