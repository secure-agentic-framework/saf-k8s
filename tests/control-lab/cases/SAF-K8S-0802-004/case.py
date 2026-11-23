"""Exercise a local firmware inventory and approval-window check in a real Kubernetes Job."""

import json
from pathlib import Path

SCOPE = "A live read-only Kubernetes Job comparing synthetic firmware and change-window records."
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
