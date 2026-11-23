"""Exercise the pinned OpenSSL provider configuration using benign test artifacts."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCOPE = (
    "One fresh Kind cluster runs a locally built OpenSSL FIPS Provider 3.5.9 fixture. "
    "The case compares default and FIPS provider behavior, validates the fixture's module "
    "configuration, signs and verifies a harmless file using RSA-2048/SHA-256 and rejects "
    "an out-of-policy key and different artifact. Production CMVP applicability and the "
    "operational environment require separate evidence."
)


def run(lab):
    tag = f"{lab.cluster}-fips-fixture:3.5.9"
    image_id = lab.kubeconfig.parent / "fixture-image-id"
    lab.command("docker", "build", "--iidfile", str(image_id), "--tag", tag, str(HERE), timeout=600)
    try:
        lab.command("kind", "load", "docker-image", tag, "--name", lab.cluster, timeout=100)
        run_checks(lab, tag, image_id)
    finally:
        lab.command("docker", "image", "rm", tag)


def run_checks(lab, tag, image_id):
    name = "saf-fips-provider"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "data": {"probe.sh": (HERE / "provider-check.sh").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumes": [{"name": "fixture", "configMap": {"name": name}}],
        "containers": [{"name": "openssl", "image": tag, "imagePullPolicy": "Never",
                        "command": ["sh", "/fixture/probe.sh"],
                        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}],
    }})
    complete = lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                           "--timeout=70s", timeout=80, allow_failure=True)
    if complete.returncode:
        lab.kubectl("describe", "pod", name, allow_failure=True)
        lab.kubectl("logs", name, allow_failure=True)
        lab.block("The test-owned provider did not complete its fixture operations")
    output = lab.kubectl("logs", name).stdout
    findings = {
        "baseline_generated_small_key": "BASELINE_SMALL_KEY_GENERATED" in output,
        "provider_version_3_5_9": "OpenSSL 3.5.9" in output and "OpenSSL FIPS Provider" in output,
        "module_configuration_verified": "MODULE_CONFIGURATION_VERIFIED" in output,
        "out_of_policy_generation_rejected": "OUT_OF_POLICY_KEY_REJECTED" in output,
        "approved_sign_and_verify": "APPROVED_SIGN_AND_VERIFY" in output,
        "other_artifact_rejected": "OTHER_ARTIFACT_REJECTED" in output,
    }
    lab.check("red", "The default provider generates the synthetic smaller key",
              findings["baseline_generated_small_key"], {"baseline_generated_small_key": findings["baseline_generated_small_key"]})
    configured = findings["provider_version_3_5_9"] and findings["module_configuration_verified"]
    lab.check("green", "The named provider is loaded and the generated integrity configuration verifies",
              configured, {"fips_provider_3_5_9_and_configuration_verified": configured})
    denied = findings["out_of_policy_generation_rejected"]
    lab.check("green", "The configured provider rejects the same smaller key request", denied,
              {"out_of_policy_generation_rejected": denied})
    lab.check("positive", "RSA-2048 and SHA-256 sign and verify only the exact harmless artifact",
              findings["approved_sign_and_verify"] and findings["other_artifact_rejected"],
              {"approved_sign_and_verify": findings["approved_sign_and_verify"],
               "other_artifact_rejected": findings["other_artifact_rejected"]})
    (lab.evidence / "fips-provider-observations.json").write_text(json.dumps(
        {"fixture_image_id": image_id.read_text().strip(), **findings}, indent=2, sort_keys=True) + "\n")
