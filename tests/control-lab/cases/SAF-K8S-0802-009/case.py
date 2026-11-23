"""Check a fixture file against a separately mounted, immutable digest baseline."""

import hashlib
import json

SCOPE = "Live container file integrity detection over owned inert bytes, without a host mount or driver binary."
POD = "fixture-file-monitor"
BASELINE = "fixture-file-baseline"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
APPROVED = "fixture-approved-bytes"
CHANGED = "fixture-unapproved-replacement"
WRITE = "from pathlib import Path; import sys; Path('/owned/fixture.bin').write_text(sys.argv[1])"
READ = """import hashlib, json
from pathlib import Path
actual = hashlib.sha256(Path('/owned/fixture.bin').read_bytes()).hexdigest()
expected = Path('/baseline/digest').read_text().strip()
print(json.dumps({'matches': actual == expected, 'sha256': actual}))
"""


def container(name, mounts):
    return {"name": name, "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(155)"],
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "40Mi"}},
            "volumeMounts": mounts, "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}


def verify(lab):
    return json.loads(lab.kubectl("exec", POD, "-c", "monitor", "--", "python", "-c", READ).stdout)


def write(lab, content):
    lab.kubectl("exec", POD, "-c", "writer", "--", "python", "-c", WRITE, content)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    digest = hashlib.sha256(APPROVED.encode()).hexdigest()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": BASELINE}, "immutable": True,
                "data": {"digest": digest}})
    owned = {"name": "owned", "mountPath": "/owned"}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsUser": 65534, "runAsNonRoot": True, "fsGroup": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "volumes": [{"name": "owned", "emptyDir": {}}, {"name": "baseline", "configMap": {"name": BASELINE}}],
                         "containers": [container("writer", [owned]), container("monitor", [
                             dict(owned, readOnly=True), {"name": "baseline", "mountPath": "/baseline", "readOnly": True}])]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=60s", timeout=70)
    write(lab, APPROVED)
    initially_matches = verify(lab) == {"matches": True, "sha256": digest}
    write(lab, CHANGED)
    same_path = lab.kubectl("exec", POD, "-c", "monitor", "--", "test", "-f", "/owned/fixture.bin", allow_failure=True).returncode == 0
    lab.check("red", "The ordinary path check still succeeds after changing the owned file bytes",
              initially_matches and same_path, {"approved_initially_matches": initially_matches,
                                                "same_path_exists_after_replacement": same_path})

    changed = verify(lab)
    expected_change = hashlib.sha256(CHANGED.encode()).hexdigest()
    lab.check("green", "The running monitor detects a mismatch against the independent baseline",
              changed == {"matches": False, "sha256": expected_change}, {"replacement_detected": changed["matches"] is False})

    monitor_write = lab.kubectl("exec", POD, "-c", "monitor", "--", "python", "-c", WRITE, APPROVED, allow_failure=True)
    read_only = monitor_write.returncode != 0 and "Read-only file system" in monitor_write.stderr
    write(lab, APPROVED)
    recovered = verify(lab) == {"matches": True, "sha256": digest}
    lab.check("positive", "The monitor remains read-only and recognizes approved bytes after restoration",
              read_only and recovered, {"monitor_write_denied": read_only, "approved_bytes_verified": recovered})
    (lab.evidence / "file-integrity-observations.json").write_text(json.dumps({
        "initially_matches": initially_matches, "same_path_exists_after_replacement": same_path,
        "observed_changed_hash": changed, "monitor_write_denied": read_only, "approved_bytes_verified": recovered,
        "host_driver_file_tested": False}, indent=2) + "\n")
