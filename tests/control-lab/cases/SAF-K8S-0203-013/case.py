"""Compare effective Linux Security Module lockdown state on two disposable guests launched by an unprivileged Job."""

import hashlib
import json
from pathlib import Path

SCOPE = "Compare effective Linux Security Module lockdown state on two disposable guests launched by an unprivileged Job."
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
    results = set(logs.stdout.splitlines())
    observations = {}
    observations['baseline_reports_none'] = 'baseline_reports_none' in results
    lab.check('red', 'The running baseline kernel reports no lockdown',
              observations['baseline_reports_none'], {'baseline_reports_none': observations['baseline_reports_none']})
    observations['configured_guest_reports_integrity'] = 'configured_guest_reports_integrity' in results
    lab.check('green', 'The running kernel reports the selected integrity lockdown mode',
              observations['configured_guest_reports_integrity'], {'configured_guest_reports_integrity': observations['configured_guest_reports_integrity']})
    observations['same_kernel_retains_public_read'] = 'same_kernel_retains_public_read' in results
    lab.check('positive', 'The same kernel release retains ordinary procfs reads under the selected mode',
              observations['same_kernel_retains_public_read'], {'same_kernel_retains_public_read': observations['same_kernel_retains_public_read']})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "lockdown-mode-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations,
    }, indent=2) + "\n")
