"""Observe actual AppArmor complain and enforcing modes and their operation-specific evidence."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-observation"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Observe AppArmor profile behavior and attributable audit logs across complain and enforcing "
    "modes on a pinned disconnected Linux guest executed as a restricted Kind Job. Seccomp and "
    "SELinux mode details, production audit collection and workload coverage require distinct evidence."
)


def profile_job():
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
        "command": ["sh", "/fixture/boot.sh", "/fixture/profile"],
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
    profile = (HERE / "profile.apparmor").read_text()
    digest = hashlib.sha256(profile.encode()).hexdigest()
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"profile": profile,
                                            "boot.sh": (HERE / "apparmor-complain.sh").read_text()}})
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
    input_matched = f"SAF-AA-AUDIT-INPUT: {digest}" in messages
    baseline = "SAF-AA-AUDIT: both owned comparison reads are initially available" in messages
    observed = "SAF-AA-AUDIT: complain allows the implicit would-be denial and records the expected event" in messages
    enforced = "SAF-AA-AUDIT: enforcing denies both while the approved read continues" in messages
    restored = "SAF-AA-AUDIT: removing the fixture policy restores both controls" in messages
    explicit = [line.removeprefix("SAF-AA-AUDIT-EXPLICIT: ") for line in messages
                if line.startswith("SAF-AA-AUDIT-EXPLICIT: ")]
    lab.check("red", "The two owned test reads are initially available and complain mode logs the implicit would-be denial",
              baseline and observed and input_matched, {"baseline_reads": baseline, "expected_complain_event": observed,
                                                       "profile_input_matched": input_matched})
    lab.check("green", "Enforcing mode denies both fixture reads while the approved read remains available",
              enforced, {"enforcing_canaries_correct": enforced})
    lab.check("positive", "The exact compiler and kernel produce a recorded explicit-rule decision and removing policy restores both reads",
              len(explicit) == 1 and restored, {"explicit_rule_in_complain": explicit, "rollback_restored": restored})
    (lab.evidence / "apparmor-audit-observations.json").write_text(json.dumps({
        "profile_sha256": digest, "guest_image": image["Id"], "running_guest_image": status["imageID"],
        "complain_implicit_would_be_denial_event": observed, "complain_explicit_rule_decision": explicit[0],
        "enforcing_allow_deny_matrix": enforced, "rollback_restored": restored,
    }, indent=2) + "\n")
