"""Verify signed fixture bytes and reconcile their modeled device state in a Kubernetes Job."""

import json
from pathlib import Path

SCOPE = "Real integrity verification for inert evidence bytes and a Kubernetes Job evaluating modeled DPU state."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
JOB = "fixture-dpu-evidence"
CONFIG = "fixture-dpu-evidence"


def verified(lab, fixture, record):
    result = lab.command("openssl", "dgst", "-sha256", "-verify", str(fixture / "authority-public.pem"),
                         "-signature", str(fixture / "device-evidence-signature.der"), str(record), allow_failure=True)
    return result.returncode == 0 and "Verified OK" in result.stdout


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    root = Path(__file__).parent
    record = root / "device-evidence.json"
    actual = json.loads(record.read_text())
    tampered = dict(actual, revision="fixture-altered")
    changed = lab.kubeconfig.parent / "altered-device-evidence.json"
    changed.write_text(json.dumps(tampered))
    signature_ok = verified(lab, root, record)
    altered_signature_ok = verified(lab, root, changed)
    base = {"signed_record": actual, "signature_verified": signature_ok, "expected_device": "fixture-device",
            "minimum_generation": 4, "independent_boot_observation": "reviewed", "expected_revision": "fixture-approved"}
    cases = {"expected": base, "changed": dict(base, signature_verified=altered_signature_ok, signed_record=tampered),
             "wrong-device": dict(base, expected_device="fixture-other-device"),
             "stale": dict(base, minimum_generation=5), "boot-missing": dict(base, independent_boot_observation="unknown"),
             "revision-mismatch": dict(base, expected_revision="fixture-newer-approved")}
    signature_only = all(cases[name]["signature_verified"] for name in ("wrong-device", "stale", "boot-missing", "revision-mismatch"))
    lab.check("red", "Authentic bytes alone leave device binding, freshness and independent boot evidence unresolved",
              signature_only, {"signature_only_passes_wrong_device_stale_and_missing_boot": signature_only})
    data = {"observations.json": json.dumps(cases), "check-dpu-evidence.py": (root / "check-dpu-evidence.py").read_text()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "immutable": True, "data": data})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                    "containers": [{"name": "compare", "image": IMAGE, "command": ["python", "/fixture/check-dpu-evidence.py"],
                                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                    "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                  "limits": {"cpu": "100m", "memory": "40Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=60s", timeout=70)
    observed = json.loads(lab.kubectl("logs", f"job/{JOB}").stdout)
    rejected = {name: disposition for name, disposition in observed.items() if name != "expected"}
    lab.check("green", "The running policy Job distinguishes untrusted bytes and independent deployment mismatches",
              rejected == {"changed": "invalid-signature", "wrong-device": "wrong-device", "stale": "stale-evidence",
                           "boot-missing": "boot-evidence-missing", "revision-mismatch": "unexpected-revision"}, rejected)
    lab.check("positive", "The authentic fixture report and matching modeled observation remain eligible",
              observed["expected"] == "consistent-fixture", {"matching_fixture_eligible": observed["expected"] == "consistent-fixture"})
    (lab.evidence / "dpu-evidence-observations.json").write_text(json.dumps({
        "inert_signature_verified": signature_ok, "altered_signature_verified": altered_signature_ok,
        "job_results": observed, "real_firmware_or_boot_tested": False}, indent=2) + "\n")
