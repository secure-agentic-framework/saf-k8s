"""Scheduled, exact-version retrieval checks for centralized AI log classes."""
import base64
import hashlib
import json
import secrets
import subprocess
import time

from fixtures import container
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
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
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR}/audit.log"
STORE_POD = "saf-1001-039-s3"
PVC = "saf-1001-039-store"
CREDENTIALS = "saf-1001-039-synthetic-credentials"
FIXTURES = "saf-1001-039-fixtures"
INDEX_CONFIG = "saf-1001-039-index"
READER_SA = "saf-1001-039-reader"
UPLOAD_JOB = "saf-1001-039-upload"
CRONJOB = "saf-1001-039-retrieval"
BUCKET_PREFIX = "saf-k8s-1001-039"

SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster captures native audit events and case-owned training "
    "and inference workload logs. Its pinned Versity storage uses a PVC and a synthetic three-day "
    "Object Lock default. Separate scheduled Jobs retrieve the exact indexed S3 versions after "
    "gateway recreation. The reader detects a missing target and a digest-mismatched current "
    "version while healthy comparison classes stay readable. Actual production retention-window "
    "coverage, archive redundancy and authorized operational retrieval require separate evidence."
)


def object_spec(api, kind, name, **body):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def prepare_kind(_lab, temporary):
    """Mount the native kube-apiserver audit file backend into the v1.36.1 node."""
    policy = temporary / "audit-policy.yaml"
    audit_dir = temporary / "audit"
    audit_dir.mkdir()
    policy.write_text(
        "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n"
        "  - level: Metadata\n    verbs: [create]\n    resources:\n"
        '      - group: ""\n        resources: [configmaps]\n'
        f"    namespaces: [{NAMESPACE}]\n  - level: None\n"
    )
    config = temporary / "kind-audit.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR}\n        readOnly: false\n"
        "kubeadmConfigPatches:\n  - |\n    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_LOG}\n"
        "      extraVolumes:\n        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR}\n          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n"
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
        lab.block("Could not install throwaway local-archive credentials in the owned cluster")


def secret_env(key):
    return {"name": "AWS_ACCESS_KEY_ID" if key == "key-id" else "AWS_SECRET_ACCESS_KEY",
            "valueFrom": {"secretKeyRef": {"name": CREDENTIALS, "key": key}}}


def selected_audit_event(lab, marker):
    path = lab.kubeconfig.parent / "audit" / "audit.log"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.is_file():
            matches = []
            for raw in path.read_bytes().splitlines(keepends=True):
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
                lab.block("The exact fixture API request produced duplicate audit events")
        time.sleep(0.2)
    lab.block("The kube-apiserver did not persist the exact synthetic API audit event")


def make_sources(lab):
    audit_name = "saf-1001-039-audit-" + secrets.token_hex(6)
    lab.kubectl("create", "configmap", audit_name, "--from-literal=fixture=owned-synthetic")
    audit_raw, audit_record = selected_audit_event(lab, audit_name)
    if (not audit_raw.endswith(b"\n") or audit_record.get("responseStatus", {}).get("code") != 201):
        lab.block("The selected native audit event does not describe the successful fixture request")
    records = {"audit": audit_raw}
    expected = {"audit": audit_name}
    for log_class in ("training", "inference"):
        source = (CASE_DIR / "fixtures" / f"{log_class}.jsonl").read_bytes()
        pod_name = f"saf-1001-039-{log_class}"
        lab.create(object_spec("v1", "Pod", pod_name, spec={
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "emitter", "image": PYTHON_IMAGE,
                            "command": ["python", "-c", "import sys;sys.stdout.write(sys.argv[1])", source.decode()],
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                "allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]}}}],
        }))
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{pod_name}",
                    "--timeout=80s", timeout=90)
        emitted = lab.kubectl("logs", f"pod/{pod_name}").stdout.encode()
        parsed = json.loads(emitted)
        if emitted != source or parsed.get("source_log_class") != log_class:
            lab.block(f"The {log_class} emitter did not produce the exact 038 fixture bytes")
        records[log_class] = emitted
        expected[log_class] = parsed["record_id"]
    return records, expected, audit_record


def aws_runtime(pod_spec):
    """Copy the pinned AWS CLI bundle into a portable Python runtime, as in case 036."""
    runtime_mount = {"name": "aws-runtime", "mountPath": "/aws-runtime"}
    pod_spec.setdefault("securityContext", {})["fsGroup"] = 1000
    pod_spec["initContainers"] = [{
        "name": "aws-cli-bundle", "image": AWS_CLI_IMAGE,
        "command": ["/bin/sh", "-ec", "cp -R /usr/local/aws-cli/v2/current/dist/. /aws-runtime/"],
        "volumeMounts": [runtime_mount],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }]


def client_env(address, bucket, run_id):
    return [secret_env("key-id"), secret_env("key-material"),
            {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
            {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
            {"name": "AWS_MAX_ATTEMPTS", "value": "2"},
            {"name": "AWS_CLIENT_EXE", "value": "/aws-runtime/aws"},
            {"name": "AWS_ENDPOINT_URL", "value": f"http://{address}:7070"},
            {"name": "ARCHIVE_BUCKET", "value": bucket}, {"name": "RUN_ID", "value": run_id}]


def wait_job(lab, name, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["status"]
        if status.get("succeeded") == 1:
            return
        if status.get("failed"):
            output = lab.kubectl("logs", f"job/{name}", allow_failure=True).stdout
            lab.block(f"Owned Job {name} failed: {output[-500:]}")
        time.sleep(1)
    lab.block(f"Owned Job {name} did not complete")


def wait_gateway(lab):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("get", "pod", STORE_POD, "-o", "json").stdout)
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if pod["status"]["phase"] == "Failed":
            lab.kubectl("logs", STORE_POD, "-c", "gateway", "--tail=10", allow_failure=True)
            lab.block("The local versioned S3 gateway exited before readiness")
        if pod["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"):
            return pod
        time.sleep(1)
    lab.kubectl("logs", STORE_POD, "--tail=10", allow_failure=True)
    lab.block("The local versioned S3 gateway did not become ready")


def reader_template(address, bucket, mode, index_config):
    pod = {"restartPolicy": "Never", "automountServiceAccountToken": False,
           "serviceAccountName": READER_SA,
           "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "containers": [container(
               "reader", image=PYTHON_IMAGE, command=["python", "/fixture/retrieval.py"],
               env=client_env(address, bucket, "reader"),
               volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                             {"name": "index", "mountPath": "/index", "readOnly": True},
                             {"name": "aws-runtime", "mountPath": "/aws-runtime", "readOnly": True}],
               securityContext={"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsNonRoot": True, "runAsUser": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}})],
           "volumes": [{"name": "fixture", "configMap": {"name": FIXTURES,
                                                            "items": [{"key": "retrieval.py", "path": "retrieval.py"}]}},
                       {"name": "index", "configMap": {"name": index_config,
                                                          "items": [{"key": f"{mode}.json", "path": f"{mode}.json"}]}},
                       {"name": "aws-runtime", "emptyDir": {}}]}
    aws_runtime(pod)
    pod["containers"][0]["env"].append({"name": "INDEX_MODE", "value": mode})
    return {"backoffLimit": 0, "activeDeadlineSeconds": 100,
            "template": {"metadata": {"labels": {"app": "saf-1001-039-reader"}}, "spec": pod}}


def oneoff_reader(lab, name, address, bucket, mode, index_config):
    lab.create(object_spec("batch/v1", "Job", name,
                           spec=reader_template(address, bucket, mode, index_config)))
    wait_job(lab, name)
    output = lab.kubectl("logs", f"job/{name}").stdout
    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        lab.block(f"Reader {name} did not emit its structured retrieval result")
    return result


def scheduled_results(lab, owner_uid):
    deadline = time.monotonic() + 210
    while time.monotonic() < deadline:
        listing = json.loads(lab.kubectl("get", "jobs", "-o", "json").stdout)
        jobs = [row for row in listing["items"] if any(
            ref.get("kind") == "CronJob" and ref.get("uid") == owner_uid
            for ref in row["metadata"].get("ownerReferences", []))]
        completed = [row for row in jobs if row.get("status", {}).get("succeeded") == 1]
        if len(completed) >= 2:
            break
        if any(row.get("status", {}).get("failed", 0) for row in jobs):
            lab.block("An independently scheduled archive retrieval Job failed")
        time.sleep(2)
    else:
        lab.block("The CronJob did not produce two independently scheduled retrieval Jobs")
    lab.kubectl("patch", "cronjob", CRONJOB, "--type=merge", "-p", '{"spec":{"suspend":true}}')
    timestamp_key = "batch.kubernetes.io/cronjob-scheduled-timestamp"
    results = []
    for job in sorted(completed, key=lambda row: row["metadata"].get("annotations", {}).get(timestamp_key, ""))[:2]:
        meta = job["metadata"]
        pods = json.loads(lab.kubectl(
            "get", "pods", "-l", f"batch.kubernetes.io/job-name={meta['name']}", "-o", "json").stdout)["items"]
        if len(pods) != 1:
            lab.block(f"Expected one fresh reader Pod for scheduled Job {meta['name']}")
        pod = pods[0]
        if pod["spec"].get("serviceAccountName") != READER_SA:
            lab.block("A scheduled retrieval did not use the dedicated reader service account")
        output = lab.kubectl("logs", f"job/{meta['name']}").stdout
        try:
            result = json.loads(output)
        except json.JSONDecodeError:
            lab.block("A scheduled reader did not emit structured retrieval results")
        results.append({"job_uid": meta["uid"], "pod_uid": pod["metadata"]["uid"],
                        "pod_name": pod["metadata"]["name"],
                        "service_account": pod["spec"].get("serviceAccountName"),
                        "scheduled_at": meta.get("annotations", {}).get(timestamp_key),
                        "result": result})
    return results


def run(lab):
    records, record_ids, audit_record = make_sources(lab)
    for name, raw in records.items():
        (lab.evidence / f"source-{name}.jsonl").write_bytes(raw)
    (lab.evidence / "source-audit.sha256").write_text(
        hashlib.sha256(records["audit"]).hexdigest() + "  source-audit.jsonl\n")

    provisioner = lab.kubectl("get", "storageclass", "standard", "-o", "jsonpath={.provisioner}").stdout.strip()
    if provisioner != "rancher.io/local-path":
        lab.block(f"Expected the owned Kind local-path PVC provisioner, got {provisioner!r}")
    lab.create(object_spec("v1", "PersistentVolumeClaim", PVC, spec={
        "storageClassName": "standard", "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "64Mi"}},
    }))
    install_credentials(lab)
    lab.create(object_spec("v1", "ServiceAccount", READER_SA,
                           automountServiceAccountToken=False))
    mounts = [{"name": "data", "mountPath": "/data"}]
    gateway = object_spec("v1", "Pod", STORE_POD,
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
    })
    lab.create(gateway)
    store_pod = wait_gateway(lab)
    address = store_pod["status"]["podIP"]
    bucket = BUCKET_PREFIX + "-" + secrets.token_hex(4)
    run_id = secrets.token_hex(6)
    fixture_data = {"upload.py": (CASE_DIR / "fixtures" / "upload.py").read_text(),
                    "retrieval.py": (CASE_DIR / "fixtures" / "retrieval.py").read_text(),
                    **{f"{name}.jsonl": raw.decode() for name, raw in records.items()}}
    lab.create(object_spec("v1", "ConfigMap", FIXTURES, data=fixture_data))

    uploader_spec = {"backoffLimit": 0, "template": {"metadata": {"labels": {"app": UPLOAD_JOB}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [container("uploader", image=PYTHON_IMAGE,
                    command=["python", "/fixture/upload.py"],
                    env=client_env(address, bucket, run_id) + [
                        {"name": "AUDIT_RECORD_ID", "value": record_ids["audit"]},
                        {"name": "TRAINING_RECORD_ID", "value": record_ids["training"]},
                        {"name": "INFERENCE_RECORD_ID", "value": record_ids["inference"]}],
                    volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "aws-runtime", "mountPath": "/aws-runtime", "readOnly": True}],
                    securityContext={"allowPrivilegeEscalation": False,
                                     "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                                     "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}})],
                 "volumes": [{"name": "fixture", "configMap": {"name": FIXTURES}},
                             {"name": "aws-runtime", "emptyDir": {}}]}}}
    aws_runtime(uploader_spec["template"]["spec"])
    lab.create(object_spec("batch/v1", "Job", UPLOAD_JOB, spec=uploader_spec))
    wait_job(lab, UPLOAD_JOB)
    upload_raw = lab.kubectl("logs", f"job/{UPLOAD_JOB}").stdout
    try:
        upload_result = json.loads(upload_raw)
    except json.JSONDecodeError:
        lab.block("Uploader did not return the exact S3 version index")
    versioning = upload_result.get("versioning", {}).get("Status") == "Enabled"
    index = upload_result.get("index", {})
    if set(index) != {"audit", "training", "inference"}:
        lab.block("Uploader version index omitted a required AI log class")
    (lab.evidence / "upload-version-index.raw.json").write_text(json.dumps(upload_result, indent=2, sort_keys=True) + "\n")

    original_audit = index["audit"]["version_id"]
    newer = upload_result["audit_successor"]
    listed = {row["VersionId"]: row for row in upload_result["audit_versions"]
              if row["Key"] == index["audit"]["key"]}
    protected = all(row["Retention"]["Mode"] == "COMPLIANCE" for row in upload_result["protection"].values())
    lab.check("positive", "The original audit version remains retained behind a different current version",
              versioning and newer != original_audit and listed[newer]["IsLatest"]
              and not listed[original_audit]["IsLatest"] and protected,
              {"versioning_enabled": versioning, "distinct_current_version": newer != original_audit,
               "original_versions_protected": protected})

    source_volume = json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json").stdout)["spec"]["volumeName"]
    lab.kubectl("delete", "pod", STORE_POD, "--wait=true", "--timeout=60s", timeout=70)
    lab.create(gateway)
    after = wait_gateway(lab)
    after_pvc = json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json").stdout)
    same_volume = source_volume == after_pvc["spec"]["volumeName"]
    distinct_gateways = store_pod["metadata"]["uid"] != after["metadata"]["uid"]
    lab.check("positive", "The restored gateway uses the same bound archive volume",
              same_volume and distinct_gateways and after_pvc["status"]["phase"] == "Bound",
              {"same_volume": same_volume, "new_gateway_pod": distinct_gateways})
    (lab.evidence / "storage-restart.raw.json").write_text(json.dumps({
        "archive_volume_before": source_volume, "archive_volume_after": after_pvc["spec"]["volumeName"],
        "pod_uid_before": store_pod["metadata"]["uid"], "pod_uid_after": after["metadata"]["uid"],
        "pvc_uid": after_pvc["metadata"]["uid"],
    }, indent=2) + "\n")
    address = after["status"]["podIP"]

    healthy = json.dumps(index, sort_keys=True)
    bad_index = json.loads(healthy)
    bad_index["training"]["key"] = f"ai-logs/training/{run_id}/missing.jsonl"
    wrong_version = json.loads(healthy)
    wrong_version["audit"]["version_id"] = newer
    index_config = object_spec("v1", "ConfigMap", INDEX_CONFIG, immutable=True, data={
        "healthy.json": healthy, "missing.json": json.dumps(bad_index, sort_keys=True),
        "wrong-version.json": json.dumps(wrong_version, sort_keys=True),
    })
    lab.create(index_config)
    cronjob = object_spec("batch/v1", "CronJob", CRONJOB, spec={
        "schedule": "* * * * *", "timeZone": "Etc/UTC", "concurrencyPolicy": "Forbid",
        "startingDeadlineSeconds": 45, "successfulJobsHistoryLimit": 4,
        "jobTemplate": {"metadata": {"labels": {"app": CRONJOB}},
                        "spec": reader_template(address, bucket, "healthy", INDEX_CONFIG)},
    })
    created_cron = lab.create(cronjob)
    bad = oneoff_reader(lab, "saf-1001-039-detect-missing", address, bucket, "missing", INDEX_CONFIG)
    (lab.evidence / "negative-reader.raw.json").write_text(json.dumps(bad, indent=2, sort_keys=True) + "\n")
    bad_training = bad.get("classes", {}).get("training", {}).get("status")
    healthy_inference = bad.get("classes", {}).get("inference", {}).get("status")
    lab.check("red", "An independently run reader detects a missing training target while retrieving the healthy inference comparator",
              bad_training in {"version-unavailable", "object-unavailable"}
              and healthy_inference == "retrieved",
              {"missing_training_detected": bad_training in {"version-unavailable", "object-unavailable"},
               "healthy_inference_retrieved": healthy_inference == "retrieved"})

    wrong = oneoff_reader(lab, "saf-1001-039-detect-wrong-version", address, bucket, "wrong-version", INDEX_CONFIG)
    (lab.evidence / "wrong-version-reader.raw.json").write_text(json.dumps(wrong, indent=2) + "\n")
    wrong_audit = wrong["classes"]["audit"]
    correct_corruption_reason = (wrong_audit["status"] == "digest-mismatch"
                                 and wrong_audit["version_id"] == newer
                                 and wrong_audit["actual_sha256"] == upload_result["audit_successor_sha256"])
    lab.check("green", "The exact current object is detected as the wrong archived audit version",
              correct_corruption_reason and wrong["classes"]["training"]["status"] == "retrieved",
              {"wrong_audit_version_detected": correct_corruption_reason,
               "healthy_training_retrieved": wrong["classes"]["training"]["status"] == "retrieved"})

    scheduled = scheduled_results(lab, created_cron["metadata"]["uid"])
    (lab.evidence / "scheduled-reader-runs.raw.json").write_text(
        json.dumps(scheduled, indent=2, sort_keys=True) + "\n")
    distinct_jobs = scheduled[0]["job_uid"] != scheduled[1]["job_uid"]
    distinct_pods = scheduled[0]["pod_uid"] != scheduled[1]["pod_uid"]
    separate_times = bool(scheduled[0]["scheduled_at"] and scheduled[1]["scheduled_at"]
                          and scheduled[0]["scheduled_at"] < scheduled[1]["scheduled_at"])
    all_scheduled_classes = all(
        set(run["result"].get("classes", {})) == {"audit", "training", "inference"}
        and all(row.get("status") == "retrieved" for row in run["result"]["classes"].values())
        for run in scheduled)
    exact_index = all(
        run["result"]["classes"].get(log_class, {}).get("version_id") == index[log_class]["version_id"]
        and run["result"]["classes"].get(log_class, {}).get("sha256") == index[log_class]["sha256"]
        and run["result"]["classes"].get(log_class, {}).get("record", {}).get("source_log_class", log_class) == log_class
        for run in scheduled for log_class in ("audit", "training", "inference"))
    dedicated_identity = all(row["service_account"] == READER_SA for row in scheduled)
    content_observations = {"versioning_enabled": versioning, "three_classes_indexed": len(index) == 3,
                            "all_scheduled_classes_retrieved": all_scheduled_classes,
                            "exact_version_index_and_digests": exact_index}
    lab.check("green", "The scheduled checker retrieves the exact indexed versions and parsed source records for all three log classes",
              all(content_observations.values()), content_observations)
    identity_observations = {"distinct_scheduled_jobs": distinct_jobs, "distinct_reader_pods": distinct_pods,
                             "separate_schedule_ticks": separate_times,
                             "dedicated_reader_identity": dedicated_identity}
    lab.check("positive", "Separate CronJob ticks create fresh reader pods under the dedicated identity",
              all(identity_observations.values()), identity_observations)

    (lab.evidence / "retrieval-raw-evidence.json").write_text(json.dumps({
        "archive_bucket": bucket, "run_id": run_id, "pvc": json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json").stdout),
        "gateway_pod": store_pod, "native_audit_record": audit_record,
        "source_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in records.items()},
        "version_index": index, "negative_result": bad, "scheduled_runs": scheduled,
    }, indent=2, sort_keys=True) + "\n")
