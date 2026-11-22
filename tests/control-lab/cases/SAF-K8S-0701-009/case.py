"""Exercise an S3 Object Lock backend with synthetic training-artifact bytes."""
from ipaddress import IPv4Address
import json
import secrets
import subprocess
import time
from pathlib import Path

from fixtures import container


NAMESPACE = "saf-test"
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
STORE_POD = "saf-0701-009-s3"
CREDENTIALS = "saf-0701-009-synthetic-credentials"
CLIENT_JOB = "saf-0701-009-probe"
SCOPE = (
    "A disposable Kubernetes v1.36.1 kind cluster runs one digest-pinned local Versity S3 gateway "
    "server with ephemeral emptyDir storage. A pinned AWS CLI client uses documented "
    "S3 APIs and synthetic bytes/credentials to compare an unlocked baseline with "
    "COMPLIANCE-locked object versions. It checks that a same-key PUT creates a new "
    "current version while preserving the earlier locked version, that a permanent "
    "delete of the locked version is refused, and that an unversioned delete marker "
    "can hide but does not remove the retained version. No Kubernetes privileged "
    "actor, node/storage administrator, cloud provider, or provider WORM policy is tested."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def install_credentials(lab):
    fixture = object_spec("v1", "Secret", CREDENTIALS, stringData={
        "key-id": "saf-fixture-" + secrets.token_hex(8),
        "key-material": secrets.token_urlsafe(32),
    })
    # The generic runner records request bodies; keep even disposable credentials out of them.
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "create", "-f", "-"],
        input=json.dumps(fixture), text=True, capture_output=True, env=lab.env, timeout=20,
    )
    if result.returncode:
        lab.block("Could not install throwaway S3 credentials in the owned cluster")


def stored_credential(name, key):
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": CREDENTIALS, "key": key}}}


def run(lab):
    install_credentials(lab)
    lab.create(object_spec("v1", "ConfigMap", "saf-0701-009-probe-files", data={
        "run.sh": (Path(__file__).with_name("s3-probe.sh")).read_text(encoding="utf-8"),
        "baseline-v1.txt": "synthetic training baseline v1\n",
        "baseline-v2.txt": "synthetic training baseline v2\n",
        "dataset-v1.txt": "synthetic locked dataset v1\n",
        "dataset-v2.txt": "synthetic locked dataset v2\n",
        "artifact-v1.txt": "synthetic locked model artifact v1\n",
        "artifact-v2.txt": "synthetic locked model artifact v2\n",
    }))
    data_mount = [{"name": "data", "mountPath": "/data"}]
    lab.create(object_spec("v1", "Pod", STORE_POD,
                           metadata={"name": STORE_POD, "labels": {"app": STORE_POD}}, spec={
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": [container("setup", command=["mkdir", "-p", "/data/objects", "/data/versions"],
                                     volumeMounts=data_mount,
                                     securityContext={"runAsNonRoot": True, "runAsUser": 1000,
                                                      "runAsGroup": 1000, "allowPrivilegeEscalation": False,
                                                      "capabilities": {"drop": ["ALL"]}})],
        "containers": [{"name": "gateway", "image": STORE_IMAGE,
                        "args": ["--port", "0.0.0.0:7070", "posix", "--versioning-dir", "/data/versions",
                                 "/data/objects"],
                        "env": [stored_credential("ROOT_ACCESS_KEY", "key-id"),
                                stored_credential("ROOT_SECRET_KEY", "key-material")],
                        "ports": [{"name": "s3", "containerPort": 7070}],
                        "readinessProbe": {"tcpSocket": {"port": 7070}, "periodSeconds": 1},
                        "volumeMounts": data_mount,
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "capabilities": {"drop": ["ALL"]}}}],
        "volumes": [{"name": "data", "emptyDir": {}}],
    }))
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("get", "pod", STORE_POD, "-o", "json").stdout)
        phase = pod["status"]["phase"]
        if phase == "Failed":
            lab.kubectl("logs", STORE_POD, "-c", "gateway", "--tail=8", allow_failure=True)
            lab.block("The local S3 gateway exited before readiness")
        if phase == "Running":
            statuses = pod.get("status", {}).get("containerStatuses", [])
            if len(statuses) == 1 and statuses[0].get("ready"):
                address = IPv4Address(pod["status"]["podIP"])
                break
        time.sleep(1)
    else:
        lab.kubectl("logs", STORE_POD, "--tail=8", allow_failure=True)
        lab.block("The digest-pinned local S3 object store did not listen on its fixture port")

    job = object_spec("batch/v1", "Job", CLIENT_JOB, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": CLIENT_JOB}}, "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container("probe", image=AWS_CLI_IMAGE,
                                      command=["/bin/sh", "/fixture/run.sh"],
                                      env=[stored_credential("AWS_ACCESS_KEY_ID", "key-id"),
                                           stored_credential("AWS_SECRET_ACCESS_KEY", "key-material"),
                                           {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                           {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                                           {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                                           {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
                                           {"name": "HOME", "value": "/tmp"}],
                                      volumeMounts=[{"name": "probe-files", "mountPath": "/fixture",
                                                     "readOnly": True}])],
            "volumes": [{"name": "probe-files", "configMap": {"name": "saf-0701-009-probe-files"}}],
        }},
    })
    lab.create(job)
    deadline = time.monotonic() + 140
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "job", CLIENT_JOB, "-o", "json").stdout)["status"]
        if status.get("succeeded") == 1:
            break
        if status.get("failed"):
            lab.kubectl("logs", f"job/{CLIENT_JOB}", allow_failure=True)
            lab.block("The local S3 probe failed")
        time.sleep(1)
    else:
        lab.block("The local S3 probe did not finish")
    output = lab.kubectl("logs", f"job/{CLIENT_JOB}").stdout
    result = json.loads(output.splitlines()[-1])

    lab.check("red", "The same-key overwrite and permanent delete work for the unlocked benign baseline",
              result.get("baseline") == {"overwrite_visible": True, "deleted": True},
              result.get("baseline", {}))
    for label in ("dataset", "artifact"):
        observations = result[label]
        lab.check(
            "positive", f"Same-key PUT creates a new {label} version and preserves the exact locked prior contents",
            observations["versioning"] == {"new_current_version": True, "prior_unchanged": True,
                                           "retention_mode": "COMPLIANCE"},
            observations["versioning"],
        )
        lab.check(
            "green", f"Permanent deletion of a locked {label} version is denied and a delete marker preserves it",
            observations["retention"] == {"permanent_delete_denied": True, "delete_marker_created": True,
                                          "locked_version_still_readable": True},
            observations["retention"],
        )
