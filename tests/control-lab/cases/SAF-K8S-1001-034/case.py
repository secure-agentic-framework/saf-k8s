"""Check integrity of retained synthetic logs using a signed batch inventory."""
import base64
from hashlib import sha256
import json
from pathlib import Path

from fixtures import container

OPENSSL_IMAGE = (
    "docker.io/alpine/openssl:3.3.2@sha256:"
    "5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
)
HERE = Path(__file__).resolve().parent
SCOPE = (
    "Two synthetic retained batches served by a Kubernetes ConfigMap volume as the archive fixture. "
    "A pinned OpenSSL signer signs exact batch bytes and an inventory, and a separate auditor "
    "container verifies the retained bytes, detecting changes, truncation, substitution and absence. "
    "This case covers cryptographic verification. Actual centralized backends, source provenance, "
    "independent trust custody, alerting, and append-only enforcement require separate evidence."
)
PRIMARY = (
    '{"event":"training-start","result":"received"}\n'
    '{"event":"checkpoint-closed","result":"committed"}\n'
)
COMPARISON = '{"event":"inference-start","result":"received"}\n'


def config(lab, name, data, immutable=False):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": immutable, "data": data})


def mount(name, path, read_only=True):
    return {"name": name, "mountPath": path, "readOnly": read_only}


def run(lab):
    archive_records = {"intact-primary": PRIMARY, "intact-comparison": COMPARISON,
                        "changed-primary": PRIMARY.replace("committed", "rejected"),
                        "truncated-primary": PRIMARY.splitlines(keepends=True)[0],
                        "substituted-primary": COMPARISON}
    config(lab, "saf-log-audit-code", {"audit.sh": (HERE / "audit.sh").read_text()}, immutable=True)
    config(lab, "saf-log-source", {"primary.ndjson": PRIMARY, "comparison.ndjson": COMPARISON},
           immutable=True)
    config(lab, "saf-retained-archive", archive_records)
    archive_items = [{"key": key, "path": key.replace("-", "/", 1) + ".ndjson"}
                     for key in archive_records]
    audit_name = "inspect-retained-log-signatures"
    signer = container("signer", image=OPENSSL_IMAGE, command=["/bin/sh", "/code/audit.sh", "sign"],
                       volumeMounts=[mount("code", "/code"), mount("source", "/source"),
                                     mount("scratch", "/scratch", False), mount("signed", "/signed", False)])
    auditor = container("auditor", image=OPENSSL_IMAGE, command=["/bin/sh", "/code/audit.sh", "audit"],
                        volumeMounts=[mount("code", "/code"), mount("signed", "/signed"),
                                      mount("archive", "/archive")])
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": audit_name}, "spec": {
        "backoffLimit": 0, "activeDeadlineSeconds": 95,
        "template": {"spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001},
            "initContainers": [signer], "containers": [auditor],
            "volumes": [
                {"name": "code", "configMap": {"name": "saf-log-audit-code"}},
                {"name": "source", "configMap": {"name": "saf-log-source"}},
                {"name": "archive", "configMap": {"name": "saf-retained-archive", "items": archive_items}},
                {"name": "signed", "emptyDir": {"medium": "Memory"}},
                {"name": "scratch", "emptyDir": {"medium": "Memory"}},
            ],
        }},
    }})
    job = f"job/{audit_name}"
    wait = lab.kubectl("wait", "--for=condition=Complete", job, "--timeout=105s", timeout=110,
                       allow_failure=True)
    if wait.returncode:
        lab.kubectl("logs", job, "--all-containers=true", allow_failure=True)
        lab.block("The log signature audit Job did not complete")
    output = lab.kubectl("logs", job, "-c", "auditor").stdout
    values = {}
    public = {}
    for line in output.splitlines():
        name, *result = line.split()
        if name == "public":
            filename, encoded = result
            base64.b64decode(encoded, validate=True)
            public[filename] = encoded
        else:
            values[name] = result

    (lab.evidence / "retained-log-observations.json").write_text(json.dumps({
        "retained_records": archive_records,
        "digests": {name: sha256(value.encode()).hexdigest() for name, value in archive_records.items()},
        "audit": values, "signed_evidence_base64": public,
    }, indent=2) + "\n")

    altered = ("changed", "truncated", "substituted")
    baseline = {name: values[name][0] for name in altered}
    lab.check("red", "Format-only inspection accepts altered, truncated and substituted records",
              baseline == dict.fromkeys(altered, "accepted"), baseline)
    signed = {name: values[name][1] for name in (*altered, "missing")}
    lab.check("green", "Signature verification rejects changed bytes and detects the missing listed batch",
              values["inventory"] == ["verified"]
              and signed == dict.fromkeys(altered, "mismatch") | {"missing": "missing"},
              {"inventory": values["inventory"], **signed})
    positive = {name: values[name] for name in ("intact", "comparison")}
    lab.check("positive", "The original and independent comparison batches verify",
              positive == dict.fromkeys(("intact", "comparison"), ["accepted", "verified"]), positive)
