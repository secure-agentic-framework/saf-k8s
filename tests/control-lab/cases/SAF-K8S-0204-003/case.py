"""Verify measured filesystem drift and the boundary of a read-only root."""

import hashlib
import json
from pathlib import Path

SCOPE = "Two restricted Kind Jobs measure owned image-file digests and separately writable volumes from the same image."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes() + (HERE / "drift-marker.txt").read_bytes()).hexdigest()
IMAGE = "saf-lab-drift-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.drift-source"


def build(lab):
    found = lab.command("docker", "image", "inspect", IMAGE, allow_failure=True)
    if found.returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{LABEL}={SOURCE}", str(HERE), timeout=300)
        found = lab.command("docker", "image", "inspect", IMAGE)
    value, = json.loads(found.stdout)
    if value["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("Local image does not match the reviewed baseline build")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=180)


def create(lab, name, *, readonly):
    unit = {"name": "probe", "image": IMAGE, "imagePullPolicy": "Never",
            "command": ["python", "/test/probe.py"],
            "volumeMounts": [{"name": "probe", "mountPath": "/test", "readOnly": True},
                             {"name": "allowed-state", "mountPath": "/state"}],
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": readonly,
                                "capabilities": {"drop": ["ALL"]}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "probe", "configMap": {"name": "drift-probe"}},
                        {"name": "allowed-state", "emptyDir": {}},
                    ],
                }}}})


def observations(lab, name):
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=60s", timeout=70)
    probe = json.loads(lab.kubectl("logs", f"job/{name}").stdout)
    jobs = json.loads(lab.kubectl("get", "pod", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    unit, = jobs
    status, = unit["status"]["containerStatuses"]
    return {**probe, "image_id": status["imageID"]}


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    build(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "drift-probe"},
                "immutable": True, "data": {"probe.py": (HERE / "filesystem-fixture.py").read_text()}})
    create(lab, "writable-fixture", readonly=False)
    create(lab, "readonly-fixture", readonly=True)
    mutable = observations(lab, "writable-fixture")
    protected = observations(lab, "readonly-fixture")
    expected = hashlib.sha256((HERE / "drift-marker.txt").read_bytes()).hexdigest()
    changed = mutable["initial_sha256"] == expected and mutable["observed_sha256"] != expected and mutable["root_write"] == "ok"
    lab.check("red", "The approved digest matches initially and the comparator detects a real content change on the writable root",
              changed, {"root_drift_detected": changed})
    intact = protected["initial_sha256"] == protected["observed_sha256"] == expected and protected["root_write"] == "readonly"
    lab.check("green", "The read-only root refuses the same write and its approved digest remains intact",
              intact, {"protected_content_preserved": intact})
    allowed = all(row["approved_volume_writable"] for row in (mutable, protected))
    same_image = bool(mutable["image_id"]) and mutable["image_id"] == protected["image_id"]
    lab.check("positive", "The two Jobs use the same running image and retain the approved writable volume",
              allowed and same_image, {"allowed_state_writable": allowed, "same_running_image": same_image})
    (lab.evidence / "filesystem-drift-observations.json").write_text(
        json.dumps({"approved_digest": expected, "mutable": mutable, "protected": protected}, indent=2) + "\n"
    )
