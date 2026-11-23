"""Verify AppArmor profile refinement against actual uncovered behavior."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-refinement"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Verify AppArmor workload coverage and selective profile refinement in a disconnected Linux "
    "guest run by a restricted Kind Job. Two clean ordinary cycles are compared with an exercised "
    "recovery path, an excluded canary and final enforcement."
)


def profile_job():
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
        "command": ["sh", "/fixture/boot.sh", "/fixture/original", "/fixture/revision"],
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
    original = (HERE / "original.apparmor").read_text()
    revision = (HERE / "revision.apparmor").read_text()
    digests = [hashlib.sha256(text.encode()).hexdigest() for text in (original, revision)]
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"original": original, "revision": revision,
                                            "boot.sh": (HERE / "apparmor-refinement.sh").read_text()}})
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
    matched = f"SAF-REFINE-INPUT: {' '.join(digests)}" in messages
    two_cycles = "SAF-REFINE: two ordinary cycles are clean despite coverage excluding recovery" in messages
    coverage_gap = "SAF-REFINE: the original policy misses the recovery path and enforcing blocks it" in messages
    revision_ok = "SAF-REFINE: the exact revision keeps the approved paths and still denies the excluded path" in messages
    removed = "SAF-REFINE: loaded revision removed" in messages
    lab.check("red", "Two clean ordinary cycles miss a recovery violation found by the expanded, audit-calibrated probe",
              matched and two_cycles and coverage_gap, {"matched_input_revisions": matched, "ordinary_cycles_clean": two_cycles,
                                                        "recovery_gap_confirmed_under_enforcement": coverage_gap})
    lab.check("green", "The exact revised profile allows normal and recovery reads while still denying the excluded canary",
              revision_ok, {"revised_enforcement_matches_intent": revision_ok})
    lab.check("positive", "Removing the fixture profile leaves its named execution unavailable",
              removed, {"revision_removed": removed})
    (lab.evidence / "apparmor-refinement-observations.json").write_text(json.dumps({
        "original_sha256": digests[0], "revision_sha256": digests[1], "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "two_ordinary_cycles_clean": two_cycles,
        "recovery_gap_confirmed": coverage_gap, "selective_revision_enforced": revision_ok, "revision_removed": removed,
    }, indent=2) + "\n")
