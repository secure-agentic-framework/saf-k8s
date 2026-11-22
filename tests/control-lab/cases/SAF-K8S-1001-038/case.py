"""Observe per-class retention mapping for synthetic AI log records."""
import base64
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
STORE_IMAGE = (
    "ghcr.io/versity/versitygw:v1.9.0@sha256:"
    "eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7"
)
AWS_CLI_IMAGE = (
    "docker.io/amazon/aws-cli:2.27.41@sha256:"
    "bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"
)
NAMESPACE = "saf-test"
STORE_POD = "saf-1001-038-s3"
CREDENTIALS = "saf-1001-038-synthetic-credentials"
FIXTURE_CONFIG = "saf-1001-038-fixtures"
CLIENT_JOB = "saf-1001-038-probe"
BUCKET = "saf-k8s-1001-038"
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "Kubernetes v1.36.1 with actual native audit metadata and two case-owned synthetic workloads "
    "emitting training and inference logs. A local Versity S3 archive stores all three classes "
    "under distinct routes and exact version IDs. The checker compares measured active retention "
    "against a separate fixture policy, confirms correction on the older audit version and a new "
    "audit ingestion, and checks all original source bytes. Production scope and expiration behavior "
    "need separate evidence."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


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
        lab.block("Could not install throwaway credentials in the owned cluster")


def secret_env(name, key):
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": CREDENTIALS, "key": key}}}


def duration_matches(observed, created, expected_days):
    actual = (datetime.fromisoformat(observed.replace("Z", "+00:00"))
              - datetime.fromisoformat(created.replace("Z", "+00:00"))).total_seconds()
    return abs(actual - expected_days * 86400) <= 120


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


def sources(lab, case_dir):
    records = {}
    for name in ("audit", "audit-next"):
        marker = f"saf-1001-038-{name}-source"
        lab.kubectl("create", "configmap", marker, "--from-literal=fixture=owned-synthetic")
        line, event = selected_event(lab, marker)
        if (event.get("level") != "Metadata" or event.get("responseStatus", {}).get("code") != 201
                or not line.endswith(b"\n")):
            lab.block("The selected native audit event does not match the expected successful fixture operation")
        records[name] = line
    for name in ("training", "inference"):
        expected = (case_dir / "fixtures" / f"{name}.jsonl").read_bytes()
        pod = f"saf-1001-038-{name}"
        lab.create(object_spec("v1", "Pod", pod, spec={
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "emitter", "image": PYTHON_IMAGE,
                            "command": ["python", "-c", "import sys; sys.stdout.write(sys.argv[1])", expected.decode()],
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}],
        }))
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{pod}", "--timeout=80s", timeout=90)
        observed = lab.kubectl("logs", f"pod/{pod}").stdout.encode()
        if observed != expected or json.loads(observed)["source_log_class"] != name:
            lab.block(f"The {name} fixture emitted unexpected bytes or class")
        records[name] = observed
    return records


def run(lab):
    case_dir = Path(__file__).resolve().parent
    fixtures = sources(lab, case_dir)
    policy = json.loads((case_dir / "fixtures" / "retention-policy.json").read_text())
    expected = policy["approved_days"]
    initial = policy["initial_days"]
    for name, raw in fixtures.items():
        (lab.evidence / f"source-{name}.jsonl").write_bytes(raw)

    install_credentials(lab)
    store_mount = [{"name": "data", "mountPath": "/data"}]
    lab.create(object_spec("v1", "Pod", STORE_POD,
                           metadata={"name": STORE_POD, "labels": {"app": STORE_POD}}, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": [container(
            "setup", command=["mkdir", "-p", "/data/objects", "/data/versions"],
            volumeMounts=store_mount,
            securityContext={"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                             "allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"]}})],
        "containers": [{"name": "gateway", "image": STORE_IMAGE,
                        "args": ["--port", "0.0.0.0:7070", "posix", "--versioning-dir", "/data/versions",
                                 "/data/objects"],
                        "env": [secret_env("ROOT_ACCESS_KEY", "key-id"),
                                secret_env("ROOT_SECRET_KEY", "key-material")],
                        "ports": [{"name": "s3", "containerPort": 7070}],
                        "readinessProbe": {"tcpSocket": {"port": 7070}, "periodSeconds": 1},
                        "volumeMounts": store_mount,
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
        lab.block("The digest-pinned local S3 gateway did not become ready")

    probe = (case_dir / "retention-probe.sh").read_text(encoding="utf-8")
    lab.create(object_spec("v1", "ConfigMap", FIXTURE_CONFIG, data={
        "run.sh": probe,
        **{f"{name}.jsonl": data.decode() for name, data in fixtures.items()},
    }))
    run_id = secrets.token_hex(6)
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
                                           {"name": "S3_BUCKET", "value": BUCKET + "-" + run_id},
                                           {"name": "RUN_ID", "value": run_id},
                                           {"name": "AUDIT_INITIAL_DAYS", "value": str(initial["audit"])},
                                           {"name": "AUDIT_CORRECTED_DAYS", "value": str(expected["audit"])},
                                           {"name": "TRAINING_DAYS", "value": str(initial["training"])},
                                           {"name": "INFERENCE_DAYS", "value": str(initial["inference"])}],
                                      volumeMounts=[{"name": "fixtures", "mountPath": "/fixture",
                                                     "readOnly": True}])],
            "volumes": [{"name": "fixtures", "configMap": {"name": FIXTURE_CONFIG}}],
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
            lab.block("The local S3 retention-mapping probe failed")
        time.sleep(1)
    else:
        lab.block("The local S3 retention-mapping probe did not finish")
    raw_output = lab.kubectl("logs", f"job/{CLIENT_JOB}").stdout
    (lab.evidence / "retention-probe.raw.txt").write_text(raw_output)
    fields = dict(line.split("=", 1) for line in raw_output.splitlines() if "=" in line)
    created = fields["created_at"]
    initial_audit = json.loads(fields["audit.initial"])["Retention"]
    observed = {}
    for name in fixtures:
        retention = json.loads(fields[f"{name}.retention"])["Retention"]
        returned = base64.b64decode(fields[f"{name}.bytes"], validate=True)
        observed[name] = {
            "retention": retention, "key": fields[f"{name}.key"], "version": fields[f"{name}.version"],
            "stored_sha256": hashlib.sha256(returned).hexdigest(),
            "source_sha256": hashlib.sha256(fixtures[name]).hexdigest(),
            "bytes_equal": returned == fixtures[name],
        }
        (lab.evidence / f"stored-{name}.jsonl").write_bytes(returned)

    def matched(retention, day_count):
        return (retention["Mode"] == "COMPLIANCE"
                and duration_matches(retention["RetainUntilDate"], created, day_count))

    healthy = {name: matched(observed[name]["retention"], expected[name]) for name in ("training", "inference")}
    below = matched(initial_audit, initial["audit"]) and not matched(initial_audit, expected["audit"])
    lab.check("red", "The independent policy detects initial audit under-retention with two healthy comparator classes",
              below and all(healthy.values()), {"audit_below_approved": below, **healthy})
    approved = {name: matched(entry["retention"], expected["audit" if name == "audit-next" else name])
                for name, entry in observed.items()}
    lab.check("green", "Existing and newly added audit versions show the corrected retention alongside other log classes",
              all(approved.values()), approved)

    routes = all(row["key"].startswith(f"ai-logs/{'audit' if name == 'audit-next' else name}/")
                 for name, row in observed.items())
    distinct = len({row["version"] for row in observed.values()}) == len(fixtures)
    bytes_equal = all(row["bytes_equal"] for row in observed.values())
    lab.check("positive", "Each class uses its assigned archive path and returns the original source bytes",
              routes and distinct and bytes_equal,
              {"correct_routes": routes, "distinct_versions": distinct, "stored_bytes_match": bytes_equal})
    (lab.evidence / "class-retention-observations.json").write_text(json.dumps({
        "policy": policy, "compared_at": created, "audit_initial": initial_audit, "archive": observed,
    }, indent=2) + "\n")
