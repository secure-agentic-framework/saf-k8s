"""Additive Kubernetes consumer Job assertions for SAF-K8S-0906-002."""
import json
from pathlib import Path


HERE = Path(__file__).parent
NS = "saf-test"
PVC = "dataset-integrity-data"
MANIFEST = "dataset-integrity-manifest"
CODE = "dataset-integrity-code"
CONSUMER_NAMES = {
    "approved": "dataset-consumer-approved",
    "altered": "dataset-consumer-altered",
}


def _job(name, input_dir, image, claim=PVC):
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": NS},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": name}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "fsGroup": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "dataset-consumer",
                        "image": image,
                        "imagePullPolicy": "Never",
                        "command": [
                            "python", "/fixture/training_consumer.py",
                            f"/data/{input_dir}", "/manifest/manifest.json",
                        ],
                        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                        "volumeMounts": [
                            {"name": "code", "mountPath": "/fixture", "readOnly": True},
                            {"name": "manifest", "mountPath": "/manifest", "readOnly": True},
                            {"name": "dataset", "mountPath": "/data", "readOnly": True},
                        ],
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "32Mi"},
                            "limits": {"cpu": "100m", "memory": "64Mi"},
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                    }],
                    "volumes": [
                        {"name": "code", "configMap": {
                            "name": CODE,
                            "items": [
                                {"key": "dataset_fixture.py", "path": "dataset_fixture.py"},
                                {"key": "training_consumer.py", "path": "training_consumer.py"},
                            ],
                        }},
                        {"name": "manifest", "configMap": {
                            "name": MANIFEST,
                            "items": [{"key": "manifest.json", "path": "manifest.json"}],
                        }},
                        {"name": "dataset", "persistentVolumeClaim": {"claimName": claim}},
                    ],
                },
            },
        },
    }


def _run_consumer(lab, name, input_dir, image, claim=PVC):
    return _observe_job(lab, name, _job(name, input_dir, image, claim))


def _observe_job(lab, name, job):
    lab.create(job)
    lab.kubectl("-n", NS, "wait", "--for=condition=Complete", f"job/{name}",
                "--timeout=100s", timeout=110)
    completion = lab.kubectl("-n", NS, "get", "job", name,
                             "-o", "jsonpath={.status.succeeded}").stdout.strip()
    output = lab.kubectl("-n", NS, "logs", f"job/{name}").stdout.strip()
    observation = json.loads(output.splitlines()[-1])
    return completion, observation


def run(lab, image):
    approved_name = CONSUMER_NAMES["approved"]
    complete, approved = _run_consumer(lab, approved_name, "consumer-approved", image)
    expected = {
        "consumed_bytes": 16384,
        "consumed_partitions": 4,
        "consumer_started": True,
        "dataset_id": "synthetic-approved-v1",
        "decision": "accepted",
        "manifest_merkle_root": "b7c253078bb623fdab4352f577115c434eb1fef43622e5f925623d845f80f94b",
    }
    lab.check("positive", "A separate read-only Kubernetes Job consumes only the approved exact dataset",
              complete == "1" and approved == expected,
              {"job_succeeded_once": complete == "1", **approved})

    altered_name = CONSUMER_NAMES["altered"]
    complete, denied = _run_consumer(lab, altered_name, "consumer-altered", image)
    expected_denied = {
        "consumed_bytes": 0,
        "consumed_partitions": 0,
        "consumer_started": False,
        "decision": "denied",
        "reason": "digest_or_size_mismatch",
    }
    lab.check("green", "The consumer Job records denial and zero consumption for a changed segment",
              complete == "1" and denied == expected_denied,
              {"job_completed_denial_once": complete == "1", **denied})
