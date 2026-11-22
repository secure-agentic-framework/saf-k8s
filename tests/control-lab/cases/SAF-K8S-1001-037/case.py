"""Verify retention enforcement for an actual synthetic kube-apiserver audit event."""
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
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
NAMESPACE = "saf-test"
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
STORE_POD = "saf-1001-037-s3"
CREDENTIALS = "saf-1001-037-synthetic-credentials"
FIXTURE_CONFIG = "saf-1001-037-probe-files"
CLIENT_JOB = "saf-1001-037-probe"
BUCKET = "saf-k8s-1001-037-audit"
KEY = "audit/kube-apiserver-event.jsonl"
SCOPE = (
    "A fresh Kubernetes v1.36.1 kind control plane writes its native JSONL audit log to a "
    "runner-temporary directory. The case selects one actual ResponseComplete event for a "
    "case-owned synthetic ConfigMap create by exact objectRef name, hashes and preserves its "
    "raw JSONL bytes, then uploads those bytes to an isolated Versity S3 gateway backed by "
    "emptyDir. Normal S3 APIs compare permanent deletion of an unlocked version with a "
    "COMPLIANCE-retained version, verify a new version and retention shortening, exercise a delete marker, and "
    "retrieve the exact locked version. This does not establish legal retention duration, "
    "managed-provider behavior, production delivery, or production capacity/durability."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def prepare_kind(lab, temporary):
    """Expose the real kube-apiserver file backend under the runner temp directory."""
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
    return config_file


def install_credentials(lab):
    # Do not use Lab.command: its command log intentionally records request bodies.
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
    deadline = time.monotonic() + 15
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
                        and ref.get("resource") == "configmaps" and ref.get("namespace") == NAMESPACE
                        and ref.get("name") == marker):
                    matches.append((raw, event))
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                lab.block("The exact synthetic request produced duplicate matching audit events")
        time.sleep(0.25)
    lab.block("The kube-apiserver did not persist the exact synthetic request audit event")


def run(lab):
    marker = "saf-1001-037-audit-" + secrets.token_hex(8)
    lab.create(object_spec("v1", "ConfigMap", marker, data={"fixture": "synthetic audit marker"}))
    raw_event, event = selected_event(lab, marker)
    if not raw_event.endswith(b"\n"):
        lab.block("Selected native audit record was not newline-terminated JSONL")
    if event.get("level") != "Metadata" or event.get("responseStatus", {}).get("code") != 201:
        lab.block("Selected audit record does not describe the expected successful Metadata-level create")
    event_digest = hashlib.sha256(raw_event).hexdigest()
    # Preserve only the selected native event; it contains no credentials or token material.
    (lab.evidence / "selected-audit-event.jsonl").write_bytes(raw_event)
    (lab.evidence / "selected-audit-event.sha256").write_text(event_digest + "  selected-audit-event.jsonl\n")

    install_credentials(lab)
    data_mount = [{"name": "data", "mountPath": "/data"}]
    lab.create(object_spec("v1", "Pod", STORE_POD,
                           metadata={"name": STORE_POD, "labels": {"app": STORE_POD}}, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
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
                        "env": [secret_env("ROOT_ACCESS_KEY", "key-id"),
                                secret_env("ROOT_SECRET_KEY", "key-material")],
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
        if pod["status"]["phase"] == "Failed":
            lab.kubectl("logs", STORE_POD, "-c", "gateway", "--tail=8", allow_failure=True)
            lab.block("The local S3 gateway exited before readiness")
        if pod["status"]["phase"] == "Running":
            statuses = pod.get("status", {}).get("containerStatuses", [])
            if len(statuses) == 1 and statuses[0].get("ready"):
                address = pod["status"]["podIP"]
                break
        time.sleep(1)
    else:
        lab.kubectl("logs", STORE_POD, "--tail=8", allow_failure=True)
        lab.block("The digest-pinned local S3 object store did not listen on its fixture port")

    probe = Path(__file__).with_name("s3-audit-probe.sh").read_text(encoding="utf-8")
    # Audit event is a harmless metadata-level create event; raw bytes are preserved unchanged.
    lab.create(object_spec("v1", "ConfigMap", FIXTURE_CONFIG, data={
        "run.sh": probe,
        "audit-event.jsonl": raw_event.decode("utf-8"),
    }))
    job = object_spec("batch/v1", "Job", CLIENT_JOB, spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"app": CLIENT_JOB}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container("probe", image=AWS_CLI_IMAGE,
                                      command=["/bin/sh", "/fixture/run.sh"],
                                      env=[secret_env("AWS_ACCESS_KEY_ID", "key-id"),
                                           secret_env("AWS_SECRET_ACCESS_KEY", "key-material"),
                                           {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                                           {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                                           {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
                                           {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
                                           {"name": "EXPECTED_SHA256", "value": event_digest},
                                           {"name": "S3_BUCKET", "value": BUCKET},
                                           {"name": "S3_KEY", "value": KEY}],
                                      volumeMounts=[{"name": "probe-files", "mountPath": "/fixture",
                                                     "readOnly": True}])],
            "volumes": [{"name": "probe-files", "configMap": {"name": FIXTURE_CONFIG}}],
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
            lab.block("The local S3 audit-retention probe failed")
        time.sleep(1)
    else:
        lab.block("The local S3 audit-retention probe did not finish")
    raw = lab.kubectl("logs", f"job/{CLIENT_JOB}").stdout
    result = json.loads(raw)
    (lab.evidence / "s3-audit-observations.json").write_text(raw)

    versions, digests = result["versions"], result["sha256"]
    retention, errors = result["retention"], result["api_errors"]
    lab.check("red", "The same credential can permanently delete an unlocked version of the same audit bytes",
              digests["unlocked"] == event_digest
              and errors["unlocked_version"] in {"404", "NotFound", "NoSuchKey", "NoSuchVersion"},
              {"unlocked_bytes_match_native_event": digests["unlocked"] == event_digest,
               "subsequent_head": errors["unlocked_version"]})
    until = datetime.fromisoformat(retention["observed_until"].replace("Z", "+00:00"))
    configured = datetime.fromisoformat(retention["configured_until"].replace("Z", "+00:00"))
    shorter = datetime.fromisoformat(retention["shorter_until"].replace("Z", "+00:00"))
    lab.check("green", "The exact locked version retains its active COMPLIANCE period after a rejected shortening",
              retention["mode"] == "COMPLIANCE" and datetime.now(timezone.utc) < shorter < until
              and configured == until and errors["retention_shortening"] in {"AccessDenied", "InvalidRequest"},
              {"mode": retention["mode"], "configured_retention_unchanged": configured == until,
               "shortening_response": errors["retention_shortening"]})
    lab.check("green", "A distinct successor and delete marker cannot remove the retained original version",
              len(set(versions.values())) == 4 and digests["visible_successor"] != event_digest
              and errors["locked_delete"] in {"AccessDenied", "InvalidRequest"}
              and errors["current_without_version"] in {"404", "NotFound", "NoSuchKey"},
              {"distinct_version_count": len(set(versions.values())), "version_delete": errors["locked_delete"],
               "versionless_get": errors["current_without_version"]})
    lab.check("positive", "The original Kubernetes audit bytes are retrieved before and after the exact delete attempt",
              event_digest == digests["locked_before"] == digests["locked_after"],
              {"audit_bytes_match": event_digest == digests["locked_before"] == digests["locked_after"]})
