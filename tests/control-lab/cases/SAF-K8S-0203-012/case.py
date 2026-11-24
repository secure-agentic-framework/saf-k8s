"""Verify actual loading, unloading, retained loop-device operation, and fresh-boot application in disconnected guest kernels."""

import hashlib
import json
from pathlib import Path

SCOPE = "Verify actual loading, unloading, retained loop-device operation, and fresh-boot application in disconnected guest kernels."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-rootfs-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.rootfs-source"
NAME = "fixture-kernel-module-policy"


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
                             "--timeout=170s", timeout=180, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The virtual kernel fixture did not complete; inspect its owned Job result")
    lines = logs.stdout.splitlines()
    inventories = sorted(line.removeprefix("packaged_module ") for line in lines if line.startswith("packaged_module "))
    observations = {name: [line.removeprefix(f"guest {name} ") for line in lines if line.startswith(f"guest {name} ")]
                    for name in ("baseline.log", "governed.log", "fresh-boot.log")}
    baseline, governed, replacement = (set(markers) for markers in observations.values())
    baseline_actions = {"SAF-MODULE: baseline-load-allowed", "SAF-MODULE: baseline-unload-allowed"}
    lab.check("red", "Without the freeze, the pinned stock modules load and unload in the disposable kernel",
              baseline_actions <= baseline and inventories == ["dummy", "loop"],
              {"baseline_load_and_unload_allowed": baseline_actions <= baseline,
               "packaged_module_names": inventories})
    native_denials = {"SAF-MODULE: observed-freeze", "SAF-MODULE: post-boot-load-denied",
                      "SAF-MODULE: approved-unload-denied"}
    lab.check("green", "The effective one-way freeze denies loading and unloading the same stock module actions",
              native_denials <= governed, {"freeze_active_with_loading_and_unloading_denied": native_denials <= governed})
    sticky = "SAF-MODULE: freeze-remains-after-lower-request"
    lab.check("green", "A request to reverse the active freeze fails and leaves the effective value set",
              sticky in governed, {"active_freeze_stays_set": sticky in governed})
    marker = "SAF-MODULE: approved-loop-read-succeeded"
    lab.check("positive", "The boot-approved loop module still reads an actual owned block marker",
              marker in governed, {"retained_loop_device_read_succeeded": marker in governed})
    kernels = [{line for line in group if line.startswith("SAF-KERNEL: ")} for group in (baseline, governed, replacement)]
    reapplied = {"SAF-MODULE: boot-starts-unfrozen", "SAF-MODULE: approved-boot-module-present", sticky, marker} | native_denials
    same = len(kernels[0]) == 1 and kernels[0] == kernels[1] == kernels[2]
    lab.check("positive", "A fresh boot reapplies the policy after the approved module and preserves its function",
              same and reapplied <= replacement,
              {"fresh_guest_reapplies_freeze_after_module_initialization": reapplied <= replacement,
               "same_pinned_kernel_boots": same})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "module-policy-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        "packaged_fixture_modules": inventories, "guest_observations": observations,
    }, indent=2) + "\n")
