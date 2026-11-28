"""Exercise a local firmware inventory and approval-window check in a real Kubernetes Job."""

import json
import base64
import hashlib
from pathlib import Path
import shutil
import runpy
import subprocess
import tempfile

SCOPE = ("A live read-only Kubernetes Job comparing synthetic firmware and change-window records, plus a separate "
         "Job verifying detached fixture signatures. An archived Hopper check verifies the device chain, signed SPDM and two signed reference manifests without current-device or revocation evidence.")
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
JOB = "fixture-firmware-inventory"
CONFIG = "fixture-firmware-inventory"


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    rows = [{"device": name, "expected": "fixture-v1", "observed": observed, "observed_at": time,
             "integrity": integrity} for name, observed, time, integrity in (
                 ("outside-window", "fixture-v2", 70, "verified"), ("inside-window", "fixture-v2", 52, "verified"),
                 ("unknown-integrity", "fixture-v1", 52, "not-reported"), ("unchanged", "fixture-v1", 52, "verified"))]
    record = [{"device": name, "version": "fixture-v2", "open": 50, "close": 60, "review_id": "fixture-change-49"}
              for name in ("outside-window", "inside-window")]
    looks_approved = all(row["observed"] in {"fixture-v1", "fixture-v2"} for row in rows)
    lab.check("red", "A version allowlist alone cannot distinguish the outside-window observation",
              looks_approved, {"all_versions_pass_basic_allowlist": looks_approved})

    payload = {"inventory.json": json.dumps(rows), "windows.json": json.dumps(record),
               "check-firmware.py": Path(__file__).with_name("check-firmware.py").read_text()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "immutable": True, "data": payload})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                    "containers": [{"name": "compare", "image": IMAGE, "command": ["python", "/fixture/check-firmware.py"],
                                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                    "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                  "limits": {"cpu": "100m", "memory": "40Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=60s", timeout=70)
    observed = json.loads(lab.kubectl("logs", f"job/{JOB}").stdout)
    lab.check("green", "The running inventory check emits drift for the version seen outside its approved window",
              observed["outside-window"] == "version-drift-alert", {"outside_window": observed["outside-window"]})
    lab.check("positive", "The report distinguishes authorized, unchanged, and unverified integrity observations",
              observed == {"outside-window": "version-drift-alert", "inside-window": "approved-change",
                           "unknown-integrity": "integrity-unverified", "unchanged": "unchanged"}, observed)
    (lab.evidence / "firmware-window-observations.json").write_text(json.dumps({
        "fixture_inventory_is_synthetic": True, "job_observations": observed, "physical_firmware_measured": False}, indent=2) + "\n")

    signed_observations = _signed_observation_inputs(lab)
    signed_job = "fixture-firmware-signed-window"
    signed_config = "fixture-firmware-signed-window"
    signed_script = Path(__file__).with_name("check-signed-firmware.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": signed_config}, "immutable": True,
                "data": {"public.pem": signed_observations["public_pem"],
                         "observations.json": json.dumps(signed_observations["bundle"], sort_keys=True),
                         "check-signed-firmware.py": signed_script}})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": signed_job},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": signed_config}},
                                {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}],
                    "containers": [{"name": "verify", "image": IMAGE,
                        "command": ["python", "/fixture/check-signed-firmware.py"],
                        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                         {"name": "work", "mountPath": "/tmp"}],
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("wait", "--for=condition=complete", f"job/{signed_job}", "--timeout=60s", timeout=70)
    signed_result = json.loads(lab.kubectl("logs", f"job/{signed_job}").stdout)
    expectations = {
        "inside-window": ("valid", "approved-change"),
        "outside-window": ("valid", "version-drift-alert"),
        "changed-marker": ("invalid", "integrity-unverified"),
        "unsigned": ("absent", "integrity-unverified"),
    }
    records = {entry["scenario"]: entry["observation"] for entry in signed_observations["bundle"]["entries"]}
    expected_signed = {"public_key_sha256": signed_observations["public_key_sha256"],
                       "verification_tool_version": signed_result.get("verification_tool_version"),
                       "observations": {name: {"signature": sig, "result": result, "record": records[name]}
                                        for name, (sig, result) in expectations.items()}}
    (lab.evidence / "signed-firmware-observations.json").write_text(
        json.dumps({"synthetic_fixture_only": True, **signed_result,
                    "verifier_image": IMAGE, "physical_firmware_measured": False,
                    "private_key_retained": False}, indent=2) + "\n")
    observed = {"public_key_bound": (signed_result.get("public_key_sha256")
                                       == signed_observations["public_key_sha256"]),
                "verification_tool_version": signed_result.get("verification_tool_version"),
                "observations": signed_result.get("observations")}
    lab.check("signed_observation_window", "Only exact signature-valid observations are trusted before window classification",
              (signed_result == expected_signed and isinstance(observed["verification_tool_version"], str)
               and observed["verification_tool_version"].startswith("OpenSSL ")), observed)

    archived = runpy.run_path(str(Path(__file__).with_name("hopper_reference.py")))
    archived["run"](lab)


def _signed_observation_inputs(lab):
    if not shutil.which("openssl"):
        lab.block("The signed-observation fixture requires a local OpenSSL executable")
    inside = {"record_id": "fixture-observation-1", "device": "fixture-gpu-a",
              "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
              "observed_at": 52, "marker": "firmware-observation:fixture-fw-v2"}
    outside = {"record_id": "fixture-observation-2", "device": "fixture-gpu-a",
               "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
               "observed_at": 70, "marker": "firmware-observation:fixture-fw-v2"}
    changed = {**inside, "marker": "firmware-observation:fixture-fw-v1"}
    unsigned = dict(inside)
    windows = [{"device": "fixture-gpu-a", "version": "fixture-fw-v2", "open": 50,
                "close": 60, "review_id": "fixture-change-49"}]

    def canonical(item):
        return json.dumps(item, sort_keys=True, separators=(",", ":")).encode()

    def openssl(*args):
        result = subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            lab.block("Local OpenSSL could not generate the bounded ephemeral fixture signature")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="saf-0802-004-signer-") as scratch:
        scratch_path = Path(scratch)
        private_key = scratch_path / "fixture-private.pem"
        public_key = scratch_path / "fixture-public.pem"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key))
        openssl("pkey", "-in", str(private_key), "-pubout", "-out", str(public_key))
        public_pem = public_key.read_text()
        public_hash = hashlib.sha256(public_pem.encode()).hexdigest()
        bundle = {"windows": windows, "entries": []}
        for scenario, row in (("inside-window", inside), ("outside-window", outside)):
            payload = scratch_path / (scenario + ".json")
            signature = scratch_path / (scenario + ".sig")
            payload.write_bytes(canonical(row))
            openssl("dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(payload))
            bundle["entries"].append({"scenario": scenario, "observation": row,
                                      "signature_b64": base64.b64encode(signature.read_bytes()).decode("ascii")})
        bundle["entries"].append({"scenario": "changed-marker", "observation": changed,
                                  "signature_b64": bundle["entries"][0]["signature_b64"]})
        bundle["entries"].append({"scenario": "unsigned", "observation": unsigned, "signature_b64": ""})
    return {"public_pem": public_pem, "public_key_sha256": public_hash, "bundle": bundle}
