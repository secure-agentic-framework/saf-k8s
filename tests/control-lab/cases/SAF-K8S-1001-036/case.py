"""Check measured minimum audit retention on a local S3-compatible backend."""

import hashlib
import json
import secrets
import subprocess
import time
from pathlib import Path

from fixtures import container


CASE_DIR = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
STORE_POD = "saf-1001-036-s3"
PVC = "saf-1001-036-store"
STORAGE_CLASS = "standard"
CREDENTIALS = "saf-1001-036-synthetic-credentials"
CHECKER_CONFIG = "saf-1001-036-checker"
BUCKET = "saf-k8s-1001-036-audit"
AUDIT_KEY = "audit/synthetic-event.jsonl"
EARLIER_KEY = "audit/earlier-synthetic-event.jsonl"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)

SCOPE = (
    "A disposable Kubernetes v1.36.1 kind cluster writes one actual Metadata-level audit "
    "event for a case-owned synthetic ConfigMap create. A digest-pinned Versity v1.9.0 "
    "S3 gateway stores the event on a case-owned PVC dynamically provisioned by Kind's "
    "local-path provisioner. Repeated Jobs run the same checker against measured "
    "GetObjectLockConfiguration responses for missing, below-minimum, and corrected "
    "synthetic retention policies; the passing state also checks the retrieved "
    "GetObjectRetention applied to the stored audit event. No legal schedule is selected. "
    "This does not establish a production audit export path, deployed fleet coverage, "
    "provider behavior, long-term durability, or retention administration controls."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def prepare_kind(lab, temporary):
    policy_file = temporary / "audit-policy.yaml"
    audit_dir = temporary / "audit"
    audit_dir.mkdir()
    policy_file.write_text(
        "apiVersion: audit.k8s.io/v1\n"
        "kind: Policy\n"
        "omitStages: [RequestReceived]\n"
        "rules:\n"
        "  - level: Metadata\n"
        "    verbs: [create]\n"
        "    resources:\n"
        '      - group: ""\n'
        "        resources: [configmaps]\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "  - level: None\n"
    )
    config = temporary / "kind-audit.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy_file))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR_IN_NODE}\n"
        "        readOnly: false\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: audit-policy-file\n"
        "          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_LOG}\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n"
        "          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR_IN_NODE}\n"
        f"          mountPath: {AUDIT_DIR_IN_NODE}\n"
        "          readOnly: false\n"
        "          pathType: DirectoryOrCreate\n"
    )
    return config


def install_credentials(lab):
    secret = object_spec("v1", "Secret", CREDENTIALS, stringData={
        "key-id": "saf-fixture-" + secrets.token_hex(8),
        "key-material": secrets.token_urlsafe(32),
    })
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "create", "-f", "-"],
        input=json.dumps(secret), text=True, capture_output=True, env=lab.env, timeout=20,
    )
    if result.returncode:
        lab.block("Could not install throwaway S3 credentials in the owned cluster")


def secret_env(key):
    return {"name": "AWS_ACCESS_KEY_ID" if key == "key-id" else "AWS_SECRET_ACCESS_KEY",
            "valueFrom": {"secretKeyRef": {"name": CREDENTIALS, "key": key}}}


def selected_audit_event(lab, marker):
    path = lab.kubeconfig.parent / "audit" / "audit.log"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.is_file():
            matching = []
            for raw in path.read_bytes().splitlines(keepends=True):
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                ref = event.get("objectRef") or {}
                if (event.get("verb") == "create" and event.get("stage") == "ResponseComplete"
                        and event.get("level") == "Metadata" and ref.get("resource") == "configmaps"
                        and ref.get("namespace") == NAMESPACE and ref.get("name") == marker):
                    matching.append((raw, event))
            if len(matching) == 1:
                return matching[0]
            if len(matching) > 1:
                lab.block("The exact synthetic API request produced duplicate audit events")
        time.sleep(0.25)
    lab.block("The API server did not persist the exact synthetic audit event")


def make_gateway(lab):
    provisioner = lab.kubectl("get", "storageclass", STORAGE_CLASS,
                              "-o", "jsonpath={.provisioner}").stdout.strip()
    if provisioner != "rancher.io/local-path":
        lab.block(f"Expected Kind local-path provisioner, observed {provisioner!r}")
    lab.create(object_spec("v1", "PersistentVolumeClaim", PVC, spec={
        "storageClassName": STORAGE_CLASS, "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "64Mi"}},
    }))
    mounts = [{"name": "data", "mountPath": "/data"}]
    lab.create(object_spec("v1", "Pod", STORE_POD,
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
                                {"name": CREDENTIALS, "key": "key-id"}}},
                                {"name": "ROOT_SECRET_KEY", "valueFrom": {"secretKeyRef":
                                {"name": CREDENTIALS, "key": "key-material"}}}],
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
        lab.block("The digest-pinned S3 gateway did not become ready")
    pvc = json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json").stdout)
    pod = json.loads(lab.kubectl("get", "pod", STORE_POD, "-o", "json").stdout)
    return provisioner, pvc, pod


def create_client(lab, job):
    pod = job["spec"]["template"]["spec"]
    runtime = {"name": "aws-runtime", "mountPath": "/aws-runtime"}
    pod.setdefault("volumes", []).append({"name": "aws-runtime", "emptyDir": {}})
    pod.setdefault("securityContext", {})["fsGroup"] = 1000
    pod["initContainers"] = [{
        "name": "aws-bundle", "image": AWS_CLI_IMAGE,
        "command": ["/bin/sh", "-ec", "cp -R /usr/local/aws-cli/v2/current/dist/. /aws-runtime/"],
        "volumeMounts": [runtime],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }]
    for container in pod["containers"]:
        container["image"] = PYTHON_IMAGE
        container.setdefault("volumeMounts", []).append({**runtime, "readOnly": True})
        container["env"].append({"name": "AWS_CLIENT_EXE", "value": "/aws-runtime/aws"})
    return lab.create(job)


def job_for(lab, stage, address, object_key=None):
    spec = json.loads((CASE_DIR / "fixtures" / "policy.json").read_text())
    job_name = f"saf-1001-036-{stage}"
    create_client(lab, object_spec("batch/v1", "Job", job_name, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": job_name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "checker", "image": AWS_CLI_IMAGE,
                            "command": ["python3", "/fixture/checker.py", stage],
                            "env": [secret_env("key-id"), secret_env("key-material"),
                                    {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                    {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                                    {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                                    {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
                                    {"name": "RETENTION_BUCKET", "value": BUCKET},
                                    {"name": "RETENTION_KEY", "value": object_key or AUDIT_KEY},
                                    {"name": "SYNTHETIC_MINIMUM_DAYS", "value": str(spec["synthetic_minimum_days"])},
                                    {"name": "CHECK_OBJECT", "value": "true" if object_key else "false"}],
                            "volumeMounts": [{"name": "checker", "mountPath": "/fixture", "readOnly": True}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 1000,
                                                "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "checker", "configMap": {"name": CHECKER_CONFIG,
                          "items": [{"key": "checker.py", "path": "checker.py"}]}}],
        }},
    }))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "job", job_name, "-o", "json").stdout)["status"]
        if status.get("succeeded") == 1:
            break
        if status.get("failed"):
            logs = lab.kubectl("logs", f"job/{job_name}", allow_failure=True)
            lab.block(f"Retention checker Job failed unexpectedly: {logs.stdout[-400:]}")
        time.sleep(1)
    else:
        lab.block(f"Retention checker Job {stage} did not finish")
    output = lab.kubectl("logs", f"job/{job_name}").stdout
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        lab.block(f"Retention checker {stage} did not emit a JSON observation: {error}")
    raw_path = lab.evidence / f"raw-retention-{stage}.json"
    raw_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def parse_rule(observation):
    config = observation.get("raw_configuration", {}).get("ObjectLockConfiguration", {})
    default = ((config.get("Rule") or {}).get("DefaultRetention") or {})
    return config.get("ObjectLockEnabled") == "Enabled", default


def run(lab):
    spec = json.loads((CASE_DIR / "fixtures" / "policy.json").read_text())
    marker = "saf-1001-036-audit-" + secrets.token_hex(8)
    lab.create(object_spec("v1", "ConfigMap", marker, data={"fixture": "synthetic audit marker"}))
    raw_event, event = selected_audit_event(lab, marker)
    if (not raw_event.endswith(b"\n") or event.get("level") != "Metadata"
            or event.get("responseStatus", {}).get("code") != 201):
        lab.block("The selected native audit event is not the expected successful Metadata record")
    digest = hashlib.sha256(raw_event).hexdigest()
    (lab.evidence / "selected-audit-event.jsonl").write_bytes(raw_event)
    (lab.evidence / "selected-audit-event.sha256").write_text(
        digest + "  selected-audit-event.jsonl\n")

    install_credentials(lab)
    provisioner, pvc, store_pod = make_gateway(lab)
    address = store_pod["status"]["podIP"]
    positive_storage = (
        provisioner == "rancher.io/local-path" and pvc.get("status", {}).get("phase") == "Bound"
        and bool(pvc.get("spec", {}).get("volumeName"))
        and any(volume.get("persistentVolumeClaim", {}).get("claimName") == PVC
                for volume in store_pod.get("spec", {}).get("volumes", []))
    )
    lab.check("positive", "The Versity S3 gateway is ready on a bound Kind local-path PVC",
              positive_storage, {"local_path_provisioner": provisioner == "rancher.io/local-path",
                                "claim_bound": pvc.get("status", {}).get("phase") == "Bound",
                                "gateway_mounts_case_pvc": any(
                                    volume.get("persistentVolumeClaim", {}).get("claimName") == PVC
                                    for volume in store_pod.get("spec", {}).get("volumes", []))})

    lab.create(object_spec("v1", "ConfigMap", CHECKER_CONFIG, data={
        "checker.py": (CASE_DIR / "fixtures" / "checker.py").read_text(encoding="utf-8"),
    }))
    # This Job creates a bucket with Object Lock enabled but no default retention rule.
    bootstrap = (CASE_DIR / "fixtures" / "bootstrap.py").read_text(encoding="utf-8")
    lab.create(object_spec("v1", "ConfigMap", "saf-1001-036-bootstrap", data={"bootstrap.py": bootstrap,
        "upload.py": (CASE_DIR / "fixtures" / "upload.py").read_text(encoding="utf-8"),
        "audit-event.jsonl": raw_event.decode("utf-8")}))
    bootstrap_job = make_bootstrap_job(address)
    create_client(lab, bootstrap_job)
    wait_job(lab, "saf-1001-036-bootstrap")
    setup_raw = lab.kubectl("logs", "job/saf-1001-036-bootstrap").stdout
    setup = json.loads(setup_raw)
    (lab.evidence / "raw-retention-setup.json").write_text(json.dumps(setup, indent=2) + "\n")
    initial_config = setup.get("raw_configuration", {}).get("ObjectLockConfiguration", {})
    initial_default = ((initial_config.get("Rule") or {}).get("DefaultRetention") or {})
    if (setup.get("bucket_created") is not True or initial_config.get("ObjectLockEnabled") != "Enabled"
            or initial_default):
        lab.block("The initial bucket did not expose an enabled lock configuration without a default period")

    missing = job_for(lab, "missing", address)
    missing_enabled, missing_rule = parse_rule(missing)
    lab.check("red", "The checker detects a missing default retention period from the live bucket response",
              not missing["compliant"] and missing["reason"] == "missing_default_retention"
              and missing_enabled and not missing_rule,
              {"checker_compliant": missing["compliant"], "missing_default_detected": not bool(missing_rule),
               "object_lock_enabled": missing_enabled})

    set_policy(lab, address, spec["below_minimum_days"])
    earlier_upload = store_event(lab, address, digest, "earlier", EARLIER_KEY)
    low = job_for(lab, "below-minimum", address, EARLIER_KEY)
    low_enabled, low_rule = parse_rule(low)
    lab.check("red", "The checker detects a measured policy below the configured synthetic minimum",
              not low["compliant"] and low["reason"] == "below_synthetic_minimum"
              and low_enabled and low_rule.get("Days") == spec["below_minimum_days"]
              and low["object_retention"]["minimum_satisfied"] is False
              and low["object_retention"]["raw_retention"]["head"]["VersionId"] == earlier_upload["version_id"],
              {"checker_compliant": low["compliant"], "measured_days": low_rule.get("Days"),
               "below_synthetic_minimum": low_rule.get("Days", 0) < spec["synthetic_minimum_days"]})

    set_policy(lab, address, spec["corrected_days"])
    upload = store_event(lab, address, digest, "corrected", AUDIT_KEY)
    green = job_for(lab, "compliant", address, AUDIT_KEY)
    green_enabled, green_rule = parse_rule(green)
    lab.check("green", "The same checker accepts the measured corrected policy and its applied audit object",
              green["compliant"] and green["reason"] == "compliant"
              and green_enabled and green_rule.get("Days") == spec["corrected_days"]
              and green["object_retention"]["minimum_satisfied"] is True
              and green["object_retention"]["raw_retention"]["head"]["VersionId"] == upload["version_id"],
              {"checker_compliant": green["compliant"], "measured_days": green_rule.get("Days"),
               "object_minimum_satisfied": green.get("object_retention", {}).get("minimum_satisfied") is True,
               "mode_supported": green_rule.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}})

    earlier_after = job_for(lab, "earlier-after", address, EARLIER_KEY)
    old = low["object_retention"]["raw_retention"]
    after = earlier_after["object_retention"]["raw_retention"]
    still_older = (after["retention"] == old["retention"]
                   and after["head"]["VersionId"] == earlier_upload["version_id"])
    lab.check("positive", "The corrected bucket default governs new versions and the checker still flags the earlier version",
              still_older and not earlier_after["compliant"]
              and earlier_after["reason"] == "effective_object_retention_below_synthetic_minimum",
              {"existing_version_retention_unchanged": still_older,
               "existing_version_still_flagged": not earlier_after["compliant"]})


def store_event(lab, address, digest, stage, object_key):
    upload_job(lab, address, digest, stage, object_key)
    job_name = f"saf-1001-036-upload-{stage}"
    wait_job(lab, job_name)
    observation = json.loads(lab.kubectl("logs", f"job/{job_name}").stdout)
    (lab.evidence / f"raw-upload-{stage}.json").write_text(json.dumps(observation, indent=2) + "\n")
    if observation.get("sha256") != digest or not observation.get("version_id"):
        lab.block("S3 did not return the exact native audit event and a version ID")
    return observation


def make_bootstrap_job(address):
    config_name = "saf-1001-036-bootstrap"
    return object_spec("batch/v1", "Job", "saf-1001-036-bootstrap", spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": "saf-1001-036-bootstrap"}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "bootstrap", "image": AWS_CLI_IMAGE,
                            "command": ["python3", "/fixture/bootstrap.py"],
                            "env": [secret_env("key-id"), secret_env("key-material"),
                                    {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                    {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                                    {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                                    {"name": "RETENTION_BUCKET", "value": BUCKET}],
                            "volumeMounts": [{"name": "bootstrap", "mountPath": "/fixture", "readOnly": True}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 1000,
                                                "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "bootstrap", "configMap": {"name": config_name,
                          "items": [{"key": "bootstrap.py", "path": "bootstrap.py"},
                                    {"key": "audit-event.jsonl", "path": "audit-event.jsonl"}]}}],
        }},
    })


def upload_job(lab, address, digest, stage, object_key):
    name = f"saf-1001-036-upload-{stage}"
    return create_client(lab, object_spec("batch/v1", "Job", name, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "upload", "image": AWS_CLI_IMAGE,
                            "command": ["python3", "/fixture/upload.py"],
                            "env": [secret_env("key-id"), secret_env("key-material"),
                                    {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                    {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                                    {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                                    {"name": "RETENTION_BUCKET", "value": BUCKET},
                                    {"name": "AUDIT_KEY", "value": object_key},
                                    {"name": "EXPECTED_SHA256", "value": digest}],
                            "volumeMounts": [{"name": "upload", "mountPath": "/fixture", "readOnly": True}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 1000,
                                                "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "upload", "configMap": {"name": "saf-1001-036-bootstrap",
                          "items": [{"key": "audit-event.jsonl", "path": "audit-event.jsonl"},
                                    {"key": "upload.py", "path": "upload.py"}]}}],
        }},
    }))


def wait_job(lab, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["status"]
        if status.get("succeeded") == 1:
            return
        if status.get("failed"):
            logs = lab.kubectl("logs", f"job/{name}", allow_failure=True)
            lab.block(f"Fixture storage Job failed unexpectedly: {logs.stdout[-400:]}")
        time.sleep(1)
    lab.block(f"Fixture storage Job {name} did not finish")


def set_policy(lab, address, days):
    manifest = {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {
        "Mode": "GOVERNANCE", "Days": days}}}
    script = "import json,subprocess,sys; open('/tmp/aws-config','w').write('[default]\\ns3 =\\n    addressing_style = path\\n'); " \
             "import os; os.environ['AWS_CONFIG_FILE']='/tmp/aws-config'; subprocess.run([os.environ['AWS_CLIENT_EXE'],'--endpoint-url',sys.argv[1]," \
             "'--region','us-east-1','s3api','put-object-lock-configuration','--bucket',sys.argv[2]," \
             "'--object-lock-configuration',json.dumps(json.loads(sys.argv[3]))],check=True)"
    job_name = f"saf-1001-036-set-{days}d"
    create_client(lab, object_spec("batch/v1", "Job", job_name, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": job_name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "setter", "image": AWS_CLI_IMAGE,
                            "command": ["python3", "-c", script, f"http://{address}:7070", BUCKET,
                                        json.dumps(manifest, separators=(",", ":"))],
                            "env": [secret_env("key-id"), secret_env("key-material"),
                                    {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                    {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 1000}}],
        }},
    }))
    wait_job(lab, job_name)
