"""Observe actual Chrony reference selection in a restricted Job with two owned loopback sources and clock adjustment disabled."""

import hashlib
import json
from pathlib import Path

SCOPE = "Observe actual Chrony reference selection in a restricted Job with two owned loopback sources and clock adjustment disabled."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-clock-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.clock-source"
NAME = "fixture-chrony-reference"


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
                "immutable": True, "data": {"boot.sh": (HERE / "clock-check.sh").read_text()}})
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                          "limits": {"cpu": "150m", "memory": "96Mi"}}}
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
        lab.block("The Chrony reference fixture did not complete; inspect its owned Job result")
    results = set(logs.stdout.splitlines())
    observations = {}
    observations['absent_reference_reported'] = 'absent_reference_reported' in results
    lab.check('red', 'With no usable source, the running Chrony client reports no selected reference',
              observations['absent_reference_reported'], {'absent_reference_reported': observations['absent_reference_reported']})
    observations['alternate_reference_selected'] = 'alternate_reference_selected' in results
    lab.check('green', 'The same live client selects the available alternate after the preferred source stops',
              observations['alternate_reference_selected'], {'alternate_reference_selected': observations['alternate_reference_selected']})
    observations['preferred_reference_selected'] = 'preferred_reference_selected' in results
    lab.check('positive', 'The client selects the preferred source when both approved fixture sources are present',
              observations['preferred_reference_selected'], {'preferred_reference_selected': observations['preferred_reference_selected']})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "clock-source-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations,
    }, indent=2) + "\n")
