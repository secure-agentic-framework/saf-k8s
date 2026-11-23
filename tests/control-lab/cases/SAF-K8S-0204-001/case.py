"""Observe selected real Linux events from an owned child workload in a restricted Kubernetes Job."""

import hashlib
import json
from pathlib import Path

SCOPE = "Observe selected real Linux events from an owned child workload in a restricted Kubernetes Job."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-runtime-observation:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.runtime-source"
NAME = "fixture-runtime-events"


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
                "immutable": True, "data": {"probe.py": (HERE / "runtime-fixture.py").read_text()}})
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["python", "/test/probe.py"],
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
        lab.block("The scoped runtime observation fixture did not complete; inspect its owned Job result")
    observations = json.loads(logs.stdout)
    lab.check("red", "The public workload completes without creating a trace when collection is disabled",
              observations["workload_without_capture_emits_no_record"],
              {"disabled_capture_observed": observations["workload_without_capture_emits_no_record"]})
    required = ("owned_file_open", "loopback_connection", "known_child_executed")
    lab.check("green", "The real syscall collector sees the owned file, network and process markers",
              all(observations[name] for name in required), {name: observations[name] for name in required})
    lab.check("positive", "The owned workload retains all expected operations under scoped observation",
              observations["workload_with_capture_completed"],
              {"owned_workload_remains_functional": observations["workload_with_capture_completed"]})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "runtime-visibility-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations,
    }, indent=2) + "\n")
