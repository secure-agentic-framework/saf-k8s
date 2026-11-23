"""Verify limited AppArmor runtime recording and independently approved rule generation."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-recording"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Record operation-specific AppArmor open events in a disconnected Linux guest hosted by "
    "a restricted Kind Job. Derive a fixture policy through exact approval, compare a limited "
    "capture and representative recovery, and verify final enforcing behavior."
)


def profile_job():
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
        "command": ["sh", "/fixture/boot.sh", "/fixture/recorder", "/fixture/approved"],
        "securityContext": security,
        "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                      "limits": {"cpu": "1500m", "memory": "768Mi"}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                         {"name": "scratch", "mountPath": "/tmp"}],
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [guest],
            "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                        {"name": "scratch", "emptyDir": {}}],
        }}},
    }


def run(lab):
    recorder = (HERE / "recorder.apparmor").read_text()
    approved = (HERE / "approved-paths.txt").read_text()
    digests = [hashlib.sha256(text.encode()).hexdigest() for text in (recorder, approved)]
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"recorder": recorder, "approved": approved,
                                            "boot.sh": (HERE / "apparmor-recording.sh").read_text()}})
    lab.create(profile_job())
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=98s", timeout=108, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The AppArmor mode fixture did not complete; inspect the owned Job evidence")
    guest_pod, = rows
    status, = guest_pod["status"]["containerStatuses"]
    messages = set(logs.stdout.splitlines())
    matched = f"SAF-RECORD-INPUT: {' '.join(digests)}" in messages
    incomplete = "SAF-RECORD: first capture observes incidental use and misses a required recovery operation" in messages
    enforced = "SAF-RECORD: the reviewed generated policy preserves approved operations and excludes the observed incidental one" in messages
    removed = "SAF-RECORD: the generated fixture policy is removed" in messages
    rows = [line.split()[1:] for line in messages if line.startswith("SAF-RECORD-PROFILES: ")]
    generated = rows[0] if len(rows) == 1 else []
    distinct = len(generated) == 2 and len(set(generated)) == 2
    lab.check("red", "A limited actual recording observes incidental activity and omits recovery",
              matched and incomplete, {"matched_definitions": matched, "limited_capture_misses_recovery": incomplete})
    lab.check("green", "Representative recording plus exact approval generates a different enforcing policy with the intended boundary",
              distinct and enforced, {"generated_profiles": generated, "enforced_matrix": enforced})
    lab.check("positive", "Removing the generated profile restores the missing-profile comparison",
              removed, {"generated_profile_removed": removed})
    (lab.evidence / "apparmor-recording-observations.json").write_text(json.dumps({
        "recorder_sha256": digests[0], "approved_paths_sha256": digests[1], "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "generated_profile_digests": generated,
        "limited_capture_incomplete": incomplete, "enforcing_matrix": enforced, "generated_profile_removed": removed,
    }, indent=2) + "\n")
