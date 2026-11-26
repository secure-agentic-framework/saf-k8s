"""Verify inherited S3 COMPLIANCE retention for one native synthetic audit event."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import secrets
import subprocess
import time
from pathlib import Path

from fixtures import container


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR}/audit.log"
NAMESPACE = "saf-test"
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
REQUIRED_DAYS = 2
DEFAULT_DAYS = 3
STORE_POD = "saf-1001-027-s3"
CREDENTIALS = "saf-1001-027-synthetic-credentials"
FIXTURE_CONFIG = "saf-1001-027-probe-files"
CLIENT_JOB = "saf-1001-027-probe"
RECOVERY_JOB = "saf-1001-027-recover"
STORAGE_CLAIM = "saf-1001-027-storage"
BUCKET_PREFIX = "saf-k8s-1001-027-audit"
KEY = "audit/kube-apiserver-event.jsonl"

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind control plane writes a native Metadata-level audit "
    "event for one case-owned ConfigMap create. The case preserves that exact JSONL record and "
    "stores identical bytes in an unlocked S3 version and a version inheriting a synthetic "
    "three-day COMPLIANCE bucket default. The S3 API observations verify the configured default, "
    "effective per-version retention, successful deletion of the unlocked counterpart, denial "
    "of early protected-version deletion or shortening, and exact-version retrieval after a "
    "benign replacement. A new gateway Pod retains the locked bytes and metadata on the same bound PVC. "
    "This tests the pinned Versity gateway data plane only; it does not "
    "establish production log coverage, provider equivalence, legal retention requirements, "
    "administrative separation, storage capacity, or sustained durability."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def prepare_kind(_lab, temporary):
    """Configure the disposable API server to write native audit JSONL to the runner."""
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
    config_file = temporary / "kind-audit.yaml"
    config_file.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy_file))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR}\n"
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
        f"          hostPath: {AUDIT_DIR}\n"
        f"          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n"
        "          pathType: DirectoryOrCreate\n"
    )
    return config_file


def install_credentials(lab):
    """Install throwaway local credentials without placing their values in command evidence."""
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


def secret_env(name, key):
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": CREDENTIALS, "key": key}}}


def selected_event(lab, marker):
    audit_path = lab.kubeconfig.parent / "audit" / "audit.log"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if audit_path.is_file():
            matches = []
            for raw in audit_path.read_bytes().splitlines(keepends=True):
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                ref = event.get("objectRef") or {}
                if (event.get("verb") == "create" and event.get("stage") == "ResponseComplete"
                        and event.get("level") == "Metadata" and ref.get("resource") == "configmaps"
                        and ref.get("namespace") == NAMESPACE and ref.get("name") == marker):
                    matches.append((raw, event))
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                lab.block("The exact synthetic request produced duplicate matching audit events")
        time.sleep(0.2)
    lab.block("The kube-apiserver did not persist the exact synthetic request audit event")


def wait_gateway(lab):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("get", "pod", STORE_POD, "-o", "json").stdout)
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if pod["status"]["phase"] == "Failed":
            lab.block("The local S3 gateway exited before readiness")
        if pod["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"):
            return pod
        time.sleep(1)
    lab.block("The digest-pinned local S3 gateway did not become ready")


def wait_job(lab, name=CLIENT_JOB):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["status"]
        if status.get("succeeded") == 1:
            return
        if status.get("failed"):
            lab.block(f"The owned S3 retention probe Job {name} failed")
        time.sleep(1)
    lab.block("The S3 retention probe did not finish")


def run(lab):
    marker = "saf-1001-027-audit-" + secrets.token_hex(8)
    lab.create(object_spec("v1", "ConfigMap", marker, data={"fixture": "synthetic audit marker"}))
    raw_event, event = selected_event(lab, marker)
    if (not raw_event.endswith(b"\n") or event.get("responseStatus", {}).get("code") != 201):
        lab.block("The selected native audit event does not describe the successful fixture create")
    event_digest = hashlib.sha256(raw_event).hexdigest()
    (lab.evidence / "selected-audit-event.jsonl").write_bytes(raw_event)
    (lab.evidence / "selected-audit-event.sha256").write_text(
        event_digest + "  selected-audit-event.jsonl\n")

    install_credentials(lab)
    storage_class = json.loads(lab.kubectl("get", "storageclass", "standard", "-o", "json").stdout)
    if storage_class.get("provisioner") != "rancher.io/local-path":
        lab.block("The expected disposable local-path storage provisioner is unavailable")
    lab.create(object_spec("v1", "PersistentVolumeClaim", STORAGE_CLAIM, spec={
        "storageClassName": "standard",
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "32Mi"}},
    }))
    mounts = [{"name": "data", "mountPath": "/data"}]
    setup = container(
        "setup", command=["sh", "-c", "mkdir -p /data/objects /data/versions"],
        volumeMounts=mounts,
        securityContext={"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                        "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"}},
    )
    gateway = object_spec("v1", "Pod", STORE_POD, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": [setup],
        "containers": [{
            "name": "gateway", "image": STORE_IMAGE,
            "args": ["--port", "0.0.0.0:7070", "posix", "--versioning-dir", "/data/versions",
                     "/data/objects"],
            "env": [secret_env("ROOT_ACCESS_KEY", "key-id"),
                    secret_env("ROOT_SECRET_KEY", "key-material")],
            "ports": [{"name": "s3", "containerPort": 7070}],
            "readinessProbe": {"tcpSocket": {"port": 7070}, "periodSeconds": 1},
            "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"}},
        }],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": STORAGE_CLAIM}}],
    })
    lab.create(gateway)
    initial_pod = wait_gateway(lab)
    initial_claim = json.loads(lab.kubectl("get", "pvc", STORAGE_CLAIM, "-o", "json").stdout)
    if initial_claim.get("status", {}).get("phase") != "Bound" or not initial_claim["spec"].get("volumeName"):
        lab.block("The owned retained-object directory did not bind to a volume")
    address = initial_pod["status"]["podIP"]
    bucket = BUCKET_PREFIX + "-" + secrets.token_hex(4)
    script = (Path(__file__).with_name("s3-retention-probe.sh").read_text(encoding="utf-8"))
    lab.create(object_spec("v1", "ConfigMap", FIXTURE_CONFIG, data={
        "run.sh": script, "audit-event.jsonl": raw_event.decode("utf-8"),
    }))
    job = object_spec("batch/v1", "Job", CLIENT_JOB, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": CLIENT_JOB}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container(
                "probe", image=AWS_CLI_IMAGE, command=["/bin/sh", "/fixture/run.sh"],
                env=[secret_env("AWS_ACCESS_KEY_ID", "key-id"),
                     secret_env("AWS_SECRET_ACCESS_KEY", "key-material"),
                     {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                     {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                     {"name": "AWS_PAGER", "value": ""},
                     {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                     {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
                     {"name": "EXPECTED_SHA256", "value": event_digest},
                     {"name": "REQUIRED_DAYS", "value": str(REQUIRED_DAYS)},
                     {"name": "DEFAULT_DAYS", "value": str(DEFAULT_DAYS)},
                     {"name": "S3_BUCKET", "value": bucket},
                     {"name": "S3_KEY", "value": KEY}],
                volumeMounts=[{"name": "probe-files", "mountPath": "/fixture", "readOnly": True}],
            )],
            "volumes": [{"name": "probe-files", "configMap": {"name": FIXTURE_CONFIG}}],
        }},
    })
    lab.create(job)
    wait_job(lab)
    raw = lab.kubectl("logs", f"job/{CLIENT_JOB}").stdout
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        lab.block("The S3 retention probe did not emit structured observations")
    (lab.evidence / "s3-retention-observations.raw.json").write_text(raw)

    config = result["bucket_default"]
    effective = result["effective_retention"]
    unlocked = result["unlocked_counterpart"]
    protected = result["protected_version"]
    replacement = result["replacement"]
    required_until = datetime.fromisoformat(result["required_until"].replace("Z", "+00:00"))
    retain_until = datetime.fromisoformat(effective["retain_until"].replace("Z", "+00:00"))
    default_ok = (config["mode"] == "COMPLIANCE" and config["days"] == DEFAULT_DAYS)
    effective_ok = (effective["mode"] == "COMPLIANCE" and retain_until >= required_until
                    and retain_until > datetime.now(timezone.utc))
    lab.check(
        "green", "The bucket default is COMPLIANCE and its effective version retention meets the synthetic required window",
        default_ok and effective_ok,
        {"default_mode": config["mode"], "default_days": config["days"],
         "required_days": REQUIRED_DAYS, "effective_mode": effective["mode"],
         "effective_until_meets_required_window": retain_until >= required_until,
         "effective_retention_is_current": retain_until > datetime.now(timezone.utc)},
    )
    lab.check(
        "red", "The identical pre-default unlocked audit version can be deleted early",
        unlocked["source_sha256"] == event_digest and unlocked["deleted"]
        and unlocked["after_delete_status"] in {"404", "NoSuchKey", "NoSuchVersion", "NotFound"},
        {"same_source_bytes": unlocked["source_sha256"] == event_digest,
         "version_delete_succeeded": unlocked["deleted"],
         "version_absent_after_delete": unlocked["after_delete_status"] in
         {"404", "NoSuchKey", "NoSuchVersion", "NotFound"}},
    )
    lab.check(
        "green", "Early protected-version deletion and retention shortening are denied",
        protected["delete_denied"] and protected["delete_error"] in {"AccessDenied", "InvalidRequest"}
        and protected["shorten_denied"]
        and protected["shorten_error"] in {"AccessDenied", "InvalidRequest"}
        and protected["retention_unchanged"],
        {"version_delete_denied": protected["delete_denied"],
         "version_delete_error": protected["delete_error"],
         "shortening_denied": protected["shorten_denied"],
         "shortening_error": protected["shorten_error"],
         "effective_retention_unchanged": protected["retention_unchanged"]},
    )
    lab.check(
        "positive", "Original exact audit bytes remain retrievable by version ID after a benign replacement",
        replacement["version_id"] != effective["version_id"]
        and replacement["current_sha256"] == replacement["successor_sha256"]
        and replacement["current_sha256"] != event_digest
        and replacement["original_sha256"] == event_digest,
        {"distinct_successor_version": replacement["version_id"] != effective["version_id"],
         "successor_is_current": replacement["current_sha256"] == replacement["successor_sha256"],
         "original_exact_version_retrieved": replacement["original_sha256"] == event_digest},
    )

    lab.kubectl("delete", "pod", STORE_POD, "--wait=true", "--timeout=45s", timeout=55)
    lab.create(gateway)
    restarted = wait_gateway(lab)
    bound = json.loads(lab.kubectl("get", "pvc", STORAGE_CLAIM, "-o", "json").stdout)
    same_binding = (bound["metadata"]["uid"] == initial_claim["metadata"]["uid"]
                    and bound["spec"].get("volumeName") == initial_claim["spec"]["volumeName"])
    recovery = deepcopy(job)
    recovery["metadata"]["name"] = RECOVERY_JOB
    runner = recovery["spec"]["template"]["spec"]["containers"][0]
    runner["command"].append("recover")
    for entry in runner["env"]:
        if entry["name"] == "AWS_ENDPOINT_URL":
            entry["value"] = f'http://{restarted["status"]["podIP"]}:7070'
    runner["env"].extend([
        {"name": "LOCKED_VERSION", "value": effective["version_id"]},
        {"name": "RETAIN_UNTIL", "value": effective["retain_until"]},
        {"name": "SUCCESSOR_SHA256", "value": replacement["successor_sha256"]},
    ])
    lab.create(recovery)
    wait_job(lab, RECOVERY_JOB)
    observed = json.loads(lab.kubectl("logs", f"job/{RECOVERY_JOB}").stdout)
    expected = {"exact_version_survived": True, "same_compliance_deadline": True, "successor_still_current": True}
    new_pod = restarted["metadata"]["uid"] != initial_pod["metadata"]["uid"]
    lab.check("green", "A replacement gateway on the same bound volume preserves the exact audit version and retention",
              new_pod and same_binding and observed == expected,
              {"different_pod_uid": new_pod, "same_bound_pvc": same_binding, "storage_observations": observed})
