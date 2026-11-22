"""Exercise immutable Kubernetes lineage records and actual retrieved bytes."""
from hashlib import sha256
import json
from pathlib import Path

from fixtures import container

HERE = Path(__file__).parent
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
DATASET = {"v1": "example=1\nexample=3\n", "v2": "example=2\nexample=8\n"}
RECORDS = {"v1": "v1", "v2": "v2", "v1-reuse": "v1"}
SCOPE = (
    "Kubernetes v1.36.1 kind, immutable versioned ConfigMaps, two inert artifact and "
    "dataset byte snapshots, and independent real Jobs verifying both content digests. "
    "The previous version is retained after revision v2. Production artifact storage, "
    "authentic lineage, actual training determinism, checkpoints and retrieval "
    "permissions require separate evidence."
)


def digest(data):
    return sha256(data.encode()).hexdigest()


def configmap(lab, name, data, immutable=True):
    lab.create({"kind": "ConfigMap", "apiVersion": "v1",
                "metadata": {"name": name}, "immutable": immutable, "data": data})


def verified_job(lab, name, record, artifact, dataset, *, reject=False):
    mounts = {"code": "verification-code", "record": f"record-{record}",
              "artifact": f"artifact-{artifact}", "dataset": f"dataset-{dataset}"}
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "volumes": [{"name": volume, "configMap": {"name": map_name}}
                        for volume, map_name in mounts.items()],
            "containers": [container("verify", image=IMAGE, command=["python", "/code/verify.py"],
                                     volumeMounts=[{"name": volume, "mountPath": f"/{volume}",
                                                    "readOnly": True} for volume in mounts])],
        }}},
    })
    condition = "Failed" if reject else "Complete"
    lab.kubectl("wait", f"--for=condition={condition}", f"job/{name}", "--timeout=90s", timeout=95)
    return json.loads(lab.kubectl("logs", f"job/{name}").stdout)


def run(lab):
    configmap(lab, "verification-code", {"verify.py": (HERE / "verify.py").read_text()})
    versions = {}
    for version in ("v1", "v2"):
        artifact = (HERE / f"artifact-{version}.bin").read_text()
        configmap(lab, f"artifact-{version}", {"artifact.bin": artifact})
        configmap(lab, f"dataset-{version}", {"data.txt": DATASET[version]})
        versions[version] = digest(artifact)
    for version, data_version in RECORDS.items():
        metadata = json.loads((HERE / f"metadata-{version}.json").read_text())
        if metadata["sha256"] != versions[data_version]:
            lab.block("The declared model revision digest does not match its stored fixture")
        metadata["dataset_sha256"] = digest(DATASET[data_version])
        configmap(lab, f"record-{version}", {"record.json": json.dumps(metadata)})

    configmap(lab, "mutable-preview", {"record.json": "fixture"}, immutable=False)
    patch = ["--type=merge", "-p", '{"data":{"record.json":"synthetic replacement"}}', "--dry-run=server"]
    accepted = lab.kubectl("patch", "configmap", "mutable-preview", *patch, allow_failure=True)
    lab.check("red", "An ordinary mutable metadata record accepts a replacement",
              accepted.returncode == 0, {"mutable_replacement_admitted": accepted.returncode == 0})
    denied = lab.kubectl("patch", "configmap", "record-v1", *patch, allow_failure=True)
    immutable = denied.returncode != 0 and "field is immutable" in denied.stderr
    lab.check("green", "The API rejects replacement of the immutable versioned record",
              immutable, {"immutable_update_refused": immutable})

    first = verified_job(lab, "replay-v1", "v1", "v1", "v1")
    second = verified_job(lab, "replay-v2", "v2", "v2", "v2")
    reused = verified_job(lab, "reuse-v1", "v1-reuse", "v1", "v1")
    ordered = all(row["verified"] for row in (first, second, reused))
    lineage = (first["dataset_revision"] == reused["dataset_revision"] == "synthetic-dataset-r1"
               and second["dataset_revision"] == "synthetic-dataset-r2"
               and first["artifact_sha256"] == reused["artifact_sha256"] == versions["v1"]
               and second["artifact_sha256"] == versions["v2"] != versions["v1"])
    lab.check("positive", "Independent Jobs verify retained v1, changed v2 and reuse tied to v1",
              ordered and lineage, {"v1": first, "v2": second, "v1_reuse": reused})

    artifact_change = verified_job(lab, "deny-artifact-mismatch", "v1", "v2", "v1", reject=True)
    dataset_change = verified_job(lab, "deny-dataset-mismatch", "v1", "v1", "v2", reject=True)
    lab.check("green", "Both substituted artifact and substituted dataset bytes fail the retrieval gate",
              artifact_change["mismatches"] == ["artifact"] and dataset_change["mismatches"] == ["dataset"]
              and not artifact_change["verified"] and not dataset_change["verified"],
              {"artifact": artifact_change["mismatches"], "dataset": dataset_change["mismatches"]})
