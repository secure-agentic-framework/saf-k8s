"""Exercise actual virtual UEFI boot verification using only owned EFI markers."""

import hashlib
import json
import re
from pathlib import Path

SCOPE = "An unprivileged Kind Job observes UEFI Secure Boot decisions before and after a change to the fixture signer allowlist."
LABEL = "org.saf.fixture.toolchain-source"
NAME = "fixture-uefi-boot"
HERE = Path(__file__).resolve().parent


def toolchain(lab):
    source = hashlib.sha256()
    for name in ("Dockerfile", "marker.c"):
        source.update(name.encode())
        source.update(b"\0")
        source.update((HERE / name).read_bytes())
    fingerprint = source.hexdigest()
    image = "saf-lab-uefi-fixture:source-" + fingerprint[:24]
    lookup = lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image, allow_failure=True)
    if lookup.returncode:
        lab.command("docker", "build", "-q", "-t", image, "--label", f"{LABEL}={fingerprint}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    report = lab.command("docker", "image", "inspect", "--format", "{{json .}}", image).stdout
    metadata = json.loads(report)
    if metadata["Config"]["Labels"].get(LABEL) != fingerprint or not metadata["Id"].startswith("sha256:"):
        lab.block("The local UEFI fixture image did not match the expected toolchain source label")
    packages = lab.command("docker", "run", "--rm", "--network=none", "--entrypoint=dpkg-query",
                           metadata["Id"], "-W").stdout
    return image, metadata["Id"], hashlib.sha256(packages.encode()).hexdigest(), fingerprint


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    image, digest, packages, source = toolchain(lab)
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=180)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "data": {"boot.sh": (HERE / "boot-fixture.sh").read_text()}})
    unit = {"name": "boot", "image": image, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "150m", "memory": "128Mi"},
                          "limits": {"cpu": "1500m", "memory": "768Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 340, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                                                     {"name": "temporary", "emptyDir": {}}],
                }}}})
    complete = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                           "--timeout=350s", timeout=360, allow_failure=True)
    result = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if complete.returncode != 0 or result.returncode != 0:
        lab.block("The virtual UEFI fixture did not complete; inspect the isolated Job logs")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = pods
    status, = worker["status"]["containerStatuses"]
    actual_image = status.get("imageID", "")
    if "sha256:" not in actual_image:
        lab.block("Kubernetes did not report the virtual boot container image identity")
    rows = set(result.stdout.splitlines())
    uncovered = "unsigned_runs_without_enforcement" in rows
    enforced = "enforcement_refuses_unsigned" in rows
    approved = "signed_runs_under_enforcement" in rows
    lab.check("red", "The unsigned public EFI application executes when firmware signature enforcement is off",
              uncovered, {"unsigned_running_in_disabled_firmware": uncovered})
    lab.check("green", "The enforced firmware reports a security refusal for the unsigned application",
              enforced, {"unsigned_application_refused": enforced})
    lab.check("positive", "The same application signed by the enrolled signer executes with Secure Boot enabled",
              approved, {"approved_application_started_under_enforcement": approved, "tool_image": digest, "running_image": actual_image})
    original_signer, = re.findall(r"^original_signer ([0-9A-F]{64})$", result.stdout, re.M)
    replacement_signer, = re.findall(r"^replacement_signer ([0-9A-F]{64})$", result.stdout, re.M)
    firmware, = re.findall(r"^firmware_sha256 ([0-9a-f]{64})$", result.stdout, re.M)
    distinct = original_signer != replacement_signer
    pre_rotation_denial = "replacement_denied_by_original_allowlist" in rows
    post_rotation_approval = "replacement_allowed_by_revised_allowlist" in rows
    old_signer_denial = "original_denied_after_allowlist_replacement" in rows
    lab.check("green", "Under the original enrolled allowlist, firmware refuses the distinctly signed replacement image",
              distinct and pre_rotation_denial,
              {"different_certificate_fingerprints": distinct, "replacement_denied_by_original_policy": pre_rotation_denial})
    lab.check("positive", "Under the revised allowlist, the replacement image executes with Secure Boot still active",
              post_rotation_approval, {"replacement_executes_under_enforcement": post_rotation_approval})
    lab.check("green", "Under the revised allowlist, firmware refuses the previously approved original signer",
              old_signer_denial, {"unenrolled_original_signer_refused": old_signer_denial})
    (lab.evidence / "uefi-verified-boot-observations.json").write_text(json.dumps({
        "mechanism": "virtual UEFI with fixture-enrolled platform and signer keys",
        "docker_image": digest, "container_image": actual_image, "package_inventory_sha256": packages,
        "toolchain_source_sha256": source,
        "unsigned_disabled_runs": uncovered, "unsigned_enforced_denied": enforced,
        "approved_signed_enforced_runs": approved,
        "firmware_sha256": firmware, "original_signer_fingerprint": original_signer,
        "replacement_signer_fingerprint": replacement_signer, "replacement_initially_denied": pre_rotation_denial,
        "replacement_runs_under_revised_policy": post_rotation_approval, "original_signer_removed_denied": old_signer_denial,
        "physical_node_or_measured_boot_tested": False,
    }, indent=2) + "\n")
