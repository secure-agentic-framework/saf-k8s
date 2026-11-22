"""Measure per-version retention for synthetic AI artifact classes on Versity S3."""

import hashlib
import json
from datetime import datetime
import secrets
import subprocess
import time
from pathlib import Path

from fixtures import container


CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CASE_ID = "1001-019"
STORE_POD = f"saf-{CASE_ID}-s3"
PVC = f"saf-{CASE_ID}-store"
SECRET = f"saf-{CASE_ID}-synthetic-credentials"
CONFIG = f"saf-{CASE_ID}-fixture"
BUCKETS = {
    "historical": "saf-k8s-1001-019-history",
    "corrected": "saf-k8s-1001-019-corrected",
    "comparator": "saf-k8s-1001-019-healthy",
}

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster runs a digest-pinned Versity v1.9.0 "
    "S3 gateway on a case-owned local-path PVC. It stores three non-sensitive synthetic "
    "AI artifact classes as exact, versioned S3 objects in historical, corrected, and "
    "independent healthy-comparator buckets. Jobs use the pinned AWS CLI bundle through "
    "a Python runtime mount, read live Object Lock configuration and version-specific "
    "retention/head/get responses, including the measured policy extension on older versions. "
    "A scoped cleanup probe removes an unlocked comparator and receives a denial for the three "
    "retained versions. Production governance, deployed lifecycle rules and long-term durability "
    "require separate evidence."
)


def obj(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def secret_env(key):
    return {
        "name": "AWS_ACCESS_KEY_ID" if key == "key-id" else "AWS_SECRET_ACCESS_KEY",
        "valueFrom": {"secretKeyRef": {"name": SECRET, "key": key}},
    }


def install_credentials(lab):
    value = obj("v1", "Secret", SECRET, stringData={
        "key-id": "saf-fixture-" + secrets.token_hex(8),
        "key-material": secrets.token_urlsafe(32),
    })
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "create", "-f", "-"], input=json.dumps(value),
        text=True, capture_output=True, env=lab.env, timeout=20,
    )
    if result.returncode:
        lab.block("Could not install throwaway S3 credentials in the owned cluster")


def make_gateway(lab):
    provisioner = lab.kubectl("get", "storageclass", "standard", "-o",
                              "jsonpath={.provisioner}").stdout.strip()
    if provisioner != "rancher.io/local-path":
        lab.block(f"Expected Kind local-path provisioner, observed {provisioner!r}")
    lab.create(obj("v1", "PersistentVolumeClaim", PVC, spec={
        "storageClassName": "standard", "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "64Mi"}},
    }))
    mounts = [{"name": "data", "mountPath": "/data"}]
    lab.create(obj("v1", "Pod", STORE_POD,
                   metadata={"name": STORE_POD, "labels": {"app": STORE_POD}}, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": [container("setup", command=["mkdir", "-p", "/data/objects", "/data/versions"],
                                      volumeMounts=mounts,
                                      securityContext={"runAsNonRoot": True, "runAsUser": 1000,
                                                       "runAsGroup": 1000, "allowPrivilegeEscalation": False,
                                                       "capabilities": {"drop": ["ALL"]}})],
        "containers": [{"name": "gateway", "image": STORE_IMAGE,
                        "args": ["--port", "0.0.0.0:7070", "posix", "--versioning-dir",
                                 "/data/versions", "/data/objects"],
                        "env": [{"name": "ROOT_ACCESS_KEY", "valueFrom": {"secretKeyRef":
                                {"name": SECRET, "key": "key-id"}}},
                                {"name": "ROOT_SECRET_KEY", "valueFrom": {"secretKeyRef":
                                {"name": SECRET, "key": "key-material"}}}],
                        "ports": [{"name": "s3", "containerPort": 7070}],
                        "readinessProbe": {"tcpSocket": {"port": 7070}, "periodSeconds": 1},
                        "volumeMounts": mounts,
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "capabilities": {"drop": ["ALL"]}}}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC}}],
    }))
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("get", "pod", STORE_POD, "-o", "json").stdout)
        if pod["status"]["phase"] == "Failed":
            lab.kubectl("logs", STORE_POD, "-c", "gateway", "--tail=10", allow_failure=True)
            lab.block("The local S3 gateway exited before readiness")
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if pod["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"):
            break
        time.sleep(1)
    else:
        lab.kubectl("logs", STORE_POD, "--tail=10", allow_failure=True)
        lab.block("The digest-pinned Versity gateway did not become ready")
    pvc = json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json").stdout)
    return pod, pvc, provisioner


def portable_python_job(job):
    """Run Python fixtures with the AWS CLI copied from its pinned image."""
    spec = job["spec"]["template"]["spec"]
    runtime = {"name": "aws-runtime", "mountPath": "/aws-runtime"}
    spec.setdefault("volumes", []).append({"name": "aws-runtime", "emptyDir": {}})
    spec.setdefault("securityContext", {})["fsGroup"] = 1000
    spec["initContainers"] = [{
        "name": "aws-bundle", "image": AWS_CLI_IMAGE,
        "command": ["/bin/sh", "-ec", "cp -R /usr/local/aws-cli/v2/current/dist/. /aws-runtime/"],
        "volumeMounts": [runtime],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }]
    for item in spec["containers"]:
        item["image"] = PYTHON_IMAGE
        item.setdefault("volumeMounts", []).append({**runtime, "readOnly": True})
        item.setdefault("env", []).append({"name": "AWS_CLIENT_EXE", "value": "/aws-runtime/aws"})
    return job


def base_env(address):
    return [secret_env("key-id"), secret_env("key-material"),
            {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
            {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
            {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
            {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"}]


def job(lab, name, script, address):
    fixture = obj("batch/v1", "Job", name, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "fixture", "image": AWS_CLI_IMAGE,
                            "command": ["python3", f"/fixture/{script}"],
                            "env": base_env(address),
                            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 1000,
                                                "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
        }},
    })
    lab.create(portable_python_job(fixture))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["status"]
        if state.get("succeeded") == 1:
            output = lab.kubectl("logs", f"job/{name}").stdout
            try:
                return json.loads(output)
            except json.JSONDecodeError as error:
                lab.block(f"Fixture {name} did not emit JSON evidence: {error}")
        if state.get("failed"):
            logs = lab.kubectl("logs", f"job/{name}", allow_failure=True).stdout
            lab.block(f"Fixture {name} failed unexpectedly: {logs[-500:]}")
        time.sleep(1)
    lab.block(f"Fixture Job {name} did not finish")


def run(lab):
    policy = json.loads((CASE_DIR / "fixtures" / "policy.json").read_text())
    install_credentials(lab)
    pod, pvc, provisioner = make_gateway(lab)
    address = pod["status"]["podIP"]
    storage_ready = (provisioner == "rancher.io/local-path"
                     and pvc.get("status", {}).get("phase") == "Bound"
                     and any(v.get("persistentVolumeClaim", {}).get("claimName") == PVC
                             for v in pod.get("spec", {}).get("volumes", [])))
    lab.check("positive", "The pinned Versity gateway uses its case-owned local-path PVC",
              storage_ready, {"gateway_ready": True, "claim_bound": storage_ready,
                              "case_owned_versioned_storage": storage_ready})

    data = {
        "bootstrap.py": (CASE_DIR / "fixtures" / "bootstrap.py").read_text(),
        "probe.py": (CASE_DIR / "fixtures" / "probe.py").read_text(),
        "policy.json": json.dumps(policy, sort_keys=True),
    }
    for item in policy["classes"]:
        data[item["payload_file"]] = (CASE_DIR / "fixtures" / "payloads" / item["payload_file"]).read_text()
    lab.create(obj("v1", "ConfigMap", CONFIG, data=data))

    setup = job(lab, f"saf-{CASE_ID}-bootstrap", "bootstrap.py", address)
    (lab.evidence / "raw-retention-bucket-setup.json").write_text(json.dumps(setup, indent=2, sort_keys=True) + "\n")
    setup_ok = all(setup["buckets"][name]["versioning"].get("Status") == "Enabled"
                   and setup["buckets"][name]["lock"].get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
                   for name in BUCKETS)
    lab.check("positive", "All three fixture buckets expose versioning and Object Lock",
              setup_ok, {"bucket_count": len(BUCKETS), "versioning_enabled": setup_ok,
                         "object_lock_enabled": setup_ok})

    result = job(lab, f"saf-{CASE_ID}-probe", "probe.py", address)
    (lab.evidence / "raw-retention-object-probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    historical = result["buckets"]["historical"]
    corrected = result["buckets"]["corrected"]
    comparator = result["buckets"]["comparator"]
    history_gap = all(not historical["classes"][item["id"]]["minimum_satisfied"]
                      for item in policy["classes"])
    lab.check("red", "Live version-specific retention exposes the historical shortfall in every class",
              history_gap and historical["default_days"] == policy["historical_default_days"],
              {"historical_default_days": historical["default_days"],
               "classes_below_synthetic_minimum": sum(
                   not historical["classes"][item["id"]]["minimum_satisfied"] for item in policy["classes"]),
               "all_classes_short": history_gap})

    corrected_ok = all(corrected["classes"][item["id"]]["minimum_satisfied"]
                       for item in policy["classes"])
    comparator_ok = all(comparator["classes"][item["id"]]["minimum_satisfied"]
                        for item in policy["classes"])
    matched = all(corrected["classes"][item["id"]]["configured_days"]
                  == comparator["classes"][item["id"]]["configured_days"]
                  == item["minimum_days"] for item in policy["classes"])
    lab.check("green", "Corrected version retention meets each class threshold and matches the healthy comparator",
              corrected_ok and comparator_ok and matched,
              {"corrected_classes_satisfied": sum(
                  corrected["classes"][item["id"]]["minimum_satisfied"] for item in policy["classes"]),
               "comparator_classes_satisfied": sum(
                  comparator["classes"][item["id"]]["minimum_satisfied"] for item in policy["classes"]),
               "class_duration_settings_match": matched})

    payloads_preserved = all(
        corrected["classes"][item["id"]]["sha256"] == comparator["classes"][item["id"]]["sha256"]
        == historical["classes"][item["id"]]["sha256"]
        and corrected["classes"][item["id"]]["version_id"]
        and comparator["classes"][item["id"]]["version_id"]
        and historical["classes"][item["id"]]["version_id"]
        for item in policy["classes"])
    lab.check("positive", "The exact source bytes are retrievable from each independently versioned bucket object",
              payloads_preserved, {"class_count": len(policy["classes"]),
                                  "source_payload_digests_match": payloads_preserved,
                                  "explicit_version_ids_observed": payloads_preserved})

    correction = result["historical_after"]
    corrected_same_versions = all(
        correction[item["id"]]["version_id"] == historical["classes"][item["id"]]["version_id"]
        and correction[item["id"]]["retention"]["Mode"] == "COMPLIANCE"
        and (datetime.fromisoformat(correction[item["id"]]["retention"]["RetainUntilDate"].replace("Z", "+00:00"))
             - datetime.fromisoformat(historical["classes"][item["id"]]["last_modified"].replace("Z", "+00:00")))
             .total_seconds() >= item["minimum_days"] * 86400 - 2
        for item in policy["classes"]
    )
    lab.check("green", "Retention is corrected on the exact earlier artifact versions",
              corrected_same_versions, {"historical_versions_remediated": corrected_same_versions})
    cleanup = result["cleanup"]
    unlocked = cleanup["unlocked"] == {"returncode": 0, "error_code": None, "still_listed": False}
    protected = all(
        cleanup["locked"][item["id"]]["decision"]["returncode"] != 0
        and cleanup["locked"][item["id"]]["decision"]["error_code"] == "AccessDenied"
        and cleanup["locked"][item["id"]]["version_id"] == corrected["classes"][item["id"]]["version_id"]
        and cleanup["locked"][item["id"]]["sha256"] == corrected["classes"][item["id"]]["source_digest"]
        for item in policy["classes"]
    )
    lab.check("green", "Retention denies early cleanup of all three exact versions while the unlocked comparator is removed",
              protected and unlocked, {"unlocked_deleted": unlocked, "locked_bytes_still_available": protected})
