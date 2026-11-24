"""Observe real Linux lockdown reporting, TraceFS enforcement and monotonic mode transitions in disconnected guests."""

import hashlib
import json
from pathlib import Path

SCOPE = "Observe real Linux lockdown reporting, TraceFS enforcement and monotonic mode transitions in disconnected guests."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-rootfs-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.rootfs-source"
NAME = "fixture-kernel-lockdown"


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
                "immutable": True, "data": {"boot.sh": (HERE / "kernel-check.sh").read_text()}})
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
                             "--timeout=135s", timeout=145, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The virtual kernel fixture did not complete; inspect its owned Job result")
    lines = logs.stdout.splitlines()
    observations = {name: [line.removeprefix(f"guest {name} ") for line in lines if line.startswith(f"guest {name} ")]
                    for name in ("baseline.log", "governed.log")}
    baseline, governed = (set(observations[name]) for name in ("baseline.log", "governed.log"))
    kernel_before = {line for line in baseline if line.startswith("SAF-KERNEL: ")}
    kernel_after = {line for line in governed if line.startswith("SAF-KERNEL: ")}
    unlocked = "SAF-LOCKDOWN: [none] integrity confidentiality" in baseline
    marker_available = "SAF-TRACE: owned-marker-observed" in baseline
    lab.check("red", "The unlocked kernel reads back an owned trace marker",
              unlocked and marker_available, {"baseline_unlocked_and_marker_observed": unlocked and marker_available})
    integrity = "SAF-LOCKDOWN: none [integrity] confidentiality" in governed
    integrity_marker = "SAF-TRACE: owned-marker-observed" in governed
    lab.check("green", "The same kernel reports boot-configured integrity and retains the scoped marker operation",
              integrity and integrity_marker and len(kernel_before) == 1 and kernel_before == kernel_after,
              {"integrity_mode_active": integrity, "integrity_marker_observed": integrity_marker,
               "kernel_release_matches": len(kernel_before) == 1 and kernel_before == kernel_after})
    confidentiality = "SAF-LOCKDOWN-RAISED: none integrity [confidentiality]" in governed
    marker_denied = "SAF-TRACE: marker-denied-by-lockdown" in governed
    lab.check("green", "Native confidentiality mode denies the same trace marker through its lockdown hook",
              confidentiality and marker_denied, {"confidentiality_active": confidentiality,
                                                  "exact_trace_operation_denied": marker_denied})
    sticky = "SAF-LOCKDOWN-AFTER-LOWER-REQUEST: none integrity [confidentiality]" in governed
    readable = "SAF-LOCKDOWN: public-operational-read" in governed
    lab.check("positive", "The running guest rejects an administrative request to lower lockdown and retains uptime reads",
              sticky and readable, {"downgrade_denied_and_effective_mode_unchanged": sticky,
                                    "ordinary_uptime_read": readable})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "lockdown-mode-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        "guest_observations": observations,
    }, indent=2) + "\n")
