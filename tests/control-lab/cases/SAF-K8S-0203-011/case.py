"""Verify real read-only root policy and allowed state in an isolated Linux guest."""

import hashlib
import json
import re
from pathlib import Path

SCOPE = "An unprivileged Kind Job verifies signed fixture images and boots isolated Linux guests to check read-only root, persistent state, update and rollback."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-rootfs-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.rootfs-source"
NAME = "fixture-immutable-root"


def image(lab):
    checked = lab.command("docker", "image", "inspect", TOOLS, allow_failure=True)
    if checked.returncode:
        lab.command("docker", "build", "-q", "-t", TOOLS, "--label", f"{LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
        checked = lab.command("docker", "image", "inspect", TOOLS)
    record, = json.loads(checked.stdout)
    if record["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("The local guest fixture image does not match the tested build recipe")
    return record["Id"]


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    expected_image = image(lab)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=210)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"boot.sh": (HERE / "rootfs-fixture.sh").read_text()}})
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                          "limits": {"cpu": "1800m", "memory": "768Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "fixture", "configMap": {"name": NAME}}, {"name": "temporary", "emptyDir": {}}],
                }}}})
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=185s", timeout=195, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The virtual root fixture did not complete; inspect its owned Job result")
    results = set(logs.stdout.splitlines())
    guest = {
        log: {line.removeprefix(f"guest {log} ") for line in results if line.startswith(f"guest {log} ")}
        for log in ("baseline.log", "first.log", "replacement.log", "rollback.log")
    }
    manifests = re.findall(r"^manifest (version-one|version-two) ([a-f0-9]{64})$", logs.stdout, re.M)
    baseline = {"SAF-ROOT-MOUNT: rw", "SAF-ROOT-WRITE: allowed"} <= guest["baseline.log"]
    lab.check("red", "The writable comparison root accepts a new public marker", baseline,
              {"baseline_root_accepts_write": baseline})
    signature_rejected = "modified_manifest_signature_rejected" in results
    digest_rejected = "modified_image_digest_rejected" in results
    lab.check("green", "The same trusted public key rejects changed metadata and the authorized digest rejects changed image bytes",
              signature_rejected and digest_rejected, {"modified_manifest_rejected": signature_rejected,
                                                     "modified_image_rejected": digest_rejected})
    root_policy = {"SAF-ROOT-MOUNT: ro", "SAF-ROOT-WRITE: denied"}
    initial = root_policy | {"SAF-ROOT-RELEASE: version-one", "SAF-STATE: written"}
    lab.check("green", "The first signed root denies the write and separate permitted state accepts it",
              initial <= guest["first.log"], {"first_root_readonly": initial <= guest["first.log"]})
    replacement = root_policy | {"SAF-ROOT-RELEASE: version-two", "SAF-STATE: retained", "SAF-UPDATE-STATE: written"}
    lab.check("positive", "The verified replacement release denies root writes, reads old state and writes new state",
              replacement <= guest["replacement.log"], {"replacement_signed_root_booted": replacement <= guest["replacement.log"]})
    rollback = root_policy | {"SAF-ROOT-RELEASE: version-one", "SAF-STATE: retained", "SAF-UPDATE-STATE: retained"}
    lab.check("positive", "Re-selecting the approved prior root preserves both state markers and denies root writes",
              rollback <= guest["rollback.log"], {"signed_rollback_root_booted": rollback <= guest["rollback.log"]})
    distinct = (len(manifests) == 3 and [slot for slot, _ in manifests] == ["version-one", "version-two", "version-one"]
                and manifests[0] == manifests[2] and manifests[0][1] != manifests[1][1])
    unchanged = "both_signed_root_images_unchanged" in results
    lab.check("positive", "Every guest boot uses its expected manifest and both protected disks still verify afterwards",
              distinct and unchanged, {"signed_manifest_identity_chain": distinct,
                                        "both_root_digests_still_match": unchanged})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "immutable-root-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        "manifests": [{"approved_release": name, "root_sha256": digest} for name, digest in manifests],
        "guest_observations": {name: sorted(markers) for name, markers in guest.items()},
        "modified_manifest_rejected": signature_rejected,
        "modified_image_rejected": digest_rejected,
        "both_root_digests_still_match": unchanged,
        "fixture_guest_only": True,
    }, indent=2) + "\n")
