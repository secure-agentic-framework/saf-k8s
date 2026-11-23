"""Exercise actual virtual UEFI boot verification using only owned EFI markers."""

import json
from pathlib import Path

SCOPE = "An unprivileged Kind Job drives three isolated QEMU UEFI boots of the same benign EFI program."
TOOLS = "saf-lab-uefi-fixture:trixie"
NAME = "fixture-uefi-boot"
HERE = Path(__file__).resolve().parent


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.command("docker", "build", "-q", "-t", TOOLS, "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=180)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "data": {"boot.sh": (HERE / "boot-fixture.sh").read_text()}})
    unit = {"name": "boot", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "150m", "memory": "128Mi"},
                          "limits": {"cpu": "1500m", "memory": "768Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                                                     {"name": "temporary", "emptyDir": {}}],
                }}}})
    complete = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                           "--timeout=120s", timeout=130, allow_failure=True)
    result = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if complete.returncode != 0 or result.returncode != 0:
        lab.block("The virtual UEFI fixture did not complete; inspect the isolated Job logs")
    rows = set(result.stdout.splitlines())
    uncovered = "unsigned_runs_without_enforcement" in rows
    enforced = "enforcement_refuses_unsigned" in rows
    approved = "signed_runs_under_enforcement" in rows
    lab.check("red", "The unsigned public EFI application executes when firmware signature enforcement is off",
              uncovered, {"unsigned_running_in_disabled_firmware": uncovered})
    lab.check("green", "The enforced firmware reports a security refusal for the unsigned application",
              enforced, {"unsigned_application_refused": enforced})
    lab.check("positive", "The same application signed by the enrolled signer executes with Secure Boot enabled",
              approved, {"approved_application_started_under_enforcement": approved})
    (lab.evidence / "uefi-verified-boot-observations.json").write_text(json.dumps({
        "mechanism": "virtual UEFI with fixture-enrolled platform and signer keys",
        "unsigned_disabled_runs": uncovered, "unsigned_enforced_denied": enforced,
        "approved_signed_enforced_runs": approved, "physical_node_or_measured_boot_tested": False,
    }, indent=2) + "\n")
