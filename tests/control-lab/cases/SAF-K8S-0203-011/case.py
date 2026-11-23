"""Verify real read-only root policy and allowed state in an isolated Linux guest."""

import hashlib
import json
from pathlib import Path

SCOPE = "An unprivileged Kubernetes Job boots owned Linux guests to exercise read-only root, writable state and image replacement."
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
                             "--timeout=135s", timeout=145, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The virtual root fixture did not complete; inspect its owned Job result")
    results = set(logs.stdout.splitlines())
    baseline = "writable_baseline_changed" in results
    bounded = "verified_root_denied_and_state_written" in results
    replacement = "approved_root_replaced_and_state_retained" in results
    lab.check("red", "The writable comparison root actually accepts a new public marker", baseline,
              {"baseline_root_accepts_write": baseline})
    lab.check("green", "A real read-only guest root denies the public write while approved state accepts writes",
              bounded, {"root_write_denied": bounded, "separate_state_writable": bounded})
    lab.check("positive", "Selecting an approved replacement root preserves the allowed state and root write denial",
              replacement, {"updated_root_still_readonly": replacement, "durable_state_retained": replacement,
                            "both_protected_images_unchanged": replacement})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "immutable-root-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        "before_root_writable": baseline, "protected_root_denied": bounded, "replacement_and_state_retained": replacement,
        "production_node_image_or_verity_tested": False,
    }, indent=2) + "\n")
