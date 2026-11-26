"""Scoped recovery of inert dataset bytes on three distinct live Kubernetes PVCs."""
import json

BACKUP = "dataset-integrity-backup"
REPLACEMENT = "dataset-integrity-replacement"
RECOVERED = "recovered"
ROOT = "b7c253078bb623fdab4352f577115c434eb1fef43622e5f925623d845f80f94b"


def volume_identity(lab, namespace, claim):
    value = json.loads(lab.kubectl("-n", namespace, "get", "pvc", claim, "-o", "json").stdout)
    if value["status"]["phase"] != "Bound":
        lab.block(f"Recovery claim {claim} did not reach Bound")
    return value["metadata"]["uid"], value["spec"]["volumeName"]


def recovery_job(consumer, name, image, operation):
    job = consumer._job(name, RECOVERED, image, REPLACEMENT)
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    container["command"] = ["python", "/fixture/restore_dataset.py", operation]
    pod["volumes"][0]["configMap"]["items"].append(
        {"key": "restore_dataset.py", "path": "restore_dataset.py"}
    )
    container["volumeMounts"][2]["readOnly"] = False
    pod["volumes"].append({"name": "backup", "persistentVolumeClaim": {"claimName": BACKUP}})
    container["volumeMounts"].append(
        {"name": "backup", "mountPath": "/backup", "readOnly": operation == "restore"}
    )
    if operation == "snapshot":
        pod["volumes"].append(
            {"name": "original", "persistentVolumeClaim": {"claimName": consumer.PVC}}
        )
        container["volumeMounts"].append(
            {"name": "original", "mountPath": "/original", "readOnly": True}
        )
    return job


def run(lab, image, consumer):
    for claim in (BACKUP, REPLACEMENT):
        lab.create({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": claim, "namespace": consumer.NS},
            "spec": {"accessModes": ["ReadWriteOnce"],
                     "resources": {"requests": {"storage": "64Mi"}}},
        })

    name = "dataset-snapshot-to-backup"
    complete, backup = consumer._observe_job(
        lab, name, recovery_job(consumer, name, image, "snapshot")
    )
    claims = (consumer.PVC, BACKUP, REPLACEMENT)
    volumes = {claim: volume_identity(lab, consumer.NS, claim) for claim in claims}
    distinct = all(len(set(identifiers)) == 3 for identifiers in zip(*volumes.values()))
    valid = {"accepted": True, "reason": "verified", "merkle_root": ROOT, "partitions": 4,
             "max_workers": 2, "output_partition_count": 4}
    lab.check("positive", "A verified snapshot on a separate bound claim retains the exact commitment",
              complete == "1" and distinct and backup == {"source": valid, "target": valid},
              {"snapshot": backup, "three_distinct_bound_volumes": distinct})

    complete, denied = consumer._run_consumer(
        lab, "dataset-before-restore", RECOVERED, image, REPLACEMENT
    )
    expected_denied = {"consumed_bytes": 0, "consumed_partitions": 0, "consumer_started": False,
                       "decision": "denied", "reason": "digest_or_size_mismatch"}
    lab.check("green", "The replacement consumer denies the changed dataset before recovery",
              complete == "1" and denied == expected_denied, denied)

    name = "dataset-restore-from-backup"
    complete, restored = consumer._observe_job(
        lab, name, recovery_job(consumer, name, image, "restore")
    )
    read_complete, read_back = consumer._run_consumer(
        lab, "dataset-after-restore", RECOVERED, image, REPLACEMENT
    )
    unchanged = all(volume_identity(lab, consumer.NS, claim) == volumes[claim] for claim in claims)
    expected_read = {"consumed_bytes": 16384, "consumed_partitions": 4, "consumer_started": True,
                     "dataset_id": "synthetic-approved-v1", "decision": "accepted",
                     "manifest_merkle_root": ROOT}
    lab.check("recovery", "A fresh consumer revalidates the restored replacement and reads all four approved segments",
              complete == "1" and read_complete == "1" and unchanged
              and restored == {"source": valid, "target": valid} and read_back == expected_read,
              {"restored": restored, "consumer": read_back, "volume_identities_unchanged": unchanged})
