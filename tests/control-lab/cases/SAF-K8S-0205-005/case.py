"""Verify Pod capability admission and isolated userspace signature validation before an unattached guest BPF load."""

import hashlib
import json
from pathlib import Path

from fixtures import container, pod

SCOPE = "Verify Pod capability admission and isolated userspace signature validation before an unattached guest BPF load."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes() + (HERE / "marker.c").read_bytes()).hexdigest()
TOOLS = "saf-lab-bpf-integrity:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.bpf-source"
NAME = "fixture-bpf-integrity"


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


def capability_request(capability):
    context = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"], "add": [capability]},
               "runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}}
    return pod("fixture-capability-check", [container("marker", securityContext=context)],
               automountServiceAccountToken=False)


def run(lab):
    capabilities = ("BPF", "SYS_ADMIN")
    baseline = {cap: lab.create(capability_request(cap), dry_run=True, allow_failure=True).returncode == 0
                for cap in capabilities}
    lab.check("red", "Unrestricted admission accepts the inert capability requests as dry-runs",
              all(baseline.values()), {"baseline_dry_run_accepted": baseline})
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    denied = {}
    for cap in capabilities:
        request = lab.create(capability_request(cap), dry_run=True, allow_failure=True)
        denied[cap] = request.returncode != 0 and "capabilities.add" in request.stderr and cap in request.stderr
    expected_image = image(lab)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=210)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"boot.sh": (HERE / "integrity-fixture.sh").read_text()}})
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
        lab.block("The isolated BPF fixture did not complete; inspect its owned Job result")
    results = set(logs.stdout.splitlines())
    refused = "modified_object_rejected_before_load" in results
    lab.check("green", "Restricted admission refuses both capability requests and the fixture verifier rejects changed bytes",
              all(denied.values()) and refused, {"governed_capabilities_denied": denied, "changed_artifact_rejected": refused})
    supported = "approved_object_verifies" in results and "approved_program_loaded_and_observed" in results
    lab.check("positive", "The verified artifact loads and is independently observed in the disconnected guest",
              supported, {"approved_guest_program_observed": supported})
    observations = {"unrestricted_dry_run": baseline, "restricted_dry_run_denied": denied,
                    "changed_artifact_rejected": refused, "approved_guest_program_observed": supported}
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "bpf-integrity-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations,
    }, indent=2) + "\n")
