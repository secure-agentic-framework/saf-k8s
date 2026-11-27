"""Exercise digest-checked synthetic dataset re-ingestion across one bounded Job retry."""
import hashlib
import json
import time


NAMESPACE = "saf-test"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
LABEL_CONTROL = "saf-k8s.example/control"
LABEL_FIXTURE = "saf-k8s.example/fixture"
POSITIVE = "saf0901004-reingest-positive"
NEGATIVE = "saf0901004-reingest-negative"
POSITIVE_INPUT = POSITIVE + "-input"
NEGATIVE_INPUT = NEGATIVE + "-input"
CODE_CONFIG = "saf0901004-reingest-code"
SCRIPT = r'''import hashlib,json,os
from pathlib import Path
root=Path("/checkpoint")
fixture=Path("/fixture")
state=root/"checkpoint.json"
initial=fixture.joinpath("initial-checkpoint.json").read_bytes()
expected_initial_sha=hashlib.sha256(initial).hexdigest()
trusted=fixture.joinpath("trusted-shard.sha256").read_text(encoding="ascii").strip()
def digest(data): return hashlib.sha256(data).hexdigest()
def emit(value): print(json.dumps(value,sort_keys=True),flush=True)
mode=os.environ["MODE"]
if mode=="attempt":
    if not state.exists():
        shard=fixture.joinpath("initial-shard.json").read_bytes()
        if digest(shard)!=trusted:
            emit({"event":"initial-data-digest-mismatch","actual_sha256":digest(shard),"expected_sha256":trusted})
            raise SystemExit(22)
        root.mkdir(parents=True,exist_ok=True)
        tmp=root/"checkpoint.tmp"
        tmp.write_bytes(initial)
        os.replace(tmp,state)
        emit({"event":"initial-attempt-verified-and-checkpoint-persisted","attempt":1,
              "dataset_sha256":digest(shard),"checkpoint_sha256":digest(initial)})
        raise SystemExit(42)
    before=state.read_bytes()
    before_sha=digest(before)
    if before!=initial or before_sha!=expected_initial_sha:
        emit({"event":"checkpoint-integrity-failed-before-data-reingestion",
              "checkpoint_sha256":before_sha,"expected_sha256":expected_initial_sha})
        raise SystemExit(23)
    shard=fixture.joinpath("retry-shard.json").read_bytes()
    actual_sha=digest(shard)
    if actual_sha!=trusted:
        after_sha=digest(state.read_bytes()) if state.exists() else "missing"
        emit({"event":"retry-data-reingestion-digest-mismatch","attempt":2,
              "dataset_sha256":actual_sha,"expected_dataset_sha256":trusted,
              "checkpoint_before_sha256":before_sha,"checkpoint_after_sha256":after_sha})
        raise SystemExit(24)
    value=json.loads(initial)
    continued=json.dumps({"epoch":value["epoch"]+1,"status":"continuation-verified",
                          "previous_epoch":value["epoch"],"dataset_sha256":trusted},
                         sort_keys=True,separators=(",",":")).encode()
    tmp=root/"checkpoint.tmp"
    tmp.write_bytes(continued)
    os.replace(tmp,state)
    emit({"event":"retry-data-reingestion-verified-and-checkpoint-continued","attempt":2,
          "dataset_sha256":actual_sha,"previous_checkpoint_sha256":before_sha,
          "continued_checkpoint_sha256":digest(continued)})
    raise SystemExit(0)
if mode=="verify":
    expected=fixture.joinpath("expected-checkpoint.json").read_bytes()
    actual=state.read_bytes() if state.exists() else b""
    exact=actual==expected and digest(actual)==digest(expected)
    emit({"event":"independent-checkpoint-readback","expected_sha256":digest(expected),
          "observed_sha256":digest(actual),"exact":exact,"bytes":len(actual)})
    raise SystemExit(0 if exact else 25)
raise SystemExit(26)
'''

SHARD_APPROVED = (
    b'{"example_id":"SYNTH-0901-004-TRAIN-001","feature":"benign-fixed-value",'
    b'"label":"class-a"}\n'
)
SHARD_CHANGED = (
    b'{"example_id":"SYNTH-0901-004-TRAIN-001","feature":"changed-fixed-value",'
    b'"label":"class-a"}\n'
)
TRUSTED_SHARD_SHA256 = "ba8801fbf37150db5ff682afa8c69f53cdf38c11ddaa0e74d15783630fe16220"


def _labels():
    return {LABEL_CONTROL: "SAF-K8S-0901-004", LABEL_FIXTURE: "true"}


def _checkpoint_bytes(fixture_item):
    checkpoint = fixture_item["object"]["data"]["checkpoint.json"].encode()
    if json.loads(checkpoint) != {"epoch": 12, "status": "approved-fixture-b"}:
        raise ValueError("data re-ingestion case is outside the exact inert checkpoint fixture")
    return checkpoint


def _configmap(lab, name, checkpoint, input_shard, retry_shard, trusted_sha, expected_checkpoint):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {
            "initial-checkpoint.json": checkpoint.decode(),
            "initial-shard.json": input_shard.decode(),
            "retry-shard.json": retry_shard.decode(),
            "trusted-shard.sha256": trusted_sha,
            "expected-checkpoint.json": expected_checkpoint.decode(),
        },
    })
    observed = json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)
    data = observed.get("data", {})
    exact = (observed.get("immutable") is True and observed.get("metadata", {}).get("labels") == _labels()
             and data.get("initial-checkpoint.json", "").encode() == checkpoint
             and data.get("initial-shard.json", "").encode() == input_shard
             and data.get("retry-shard.json", "").encode() == retry_shard
             and data.get("trusted-shard.sha256") == trusted_sha
             and data.get("expected-checkpoint.json", "").encode() == expected_checkpoint)
    if not exact:
        lab.block("Re-ingestion fixture ConfigMap differs from the exact immutable input bytes")
    return {"uid": observed.get("metadata", {}).get("uid"), "immutable": True,
            "initial_checkpoint_sha256": hashlib.sha256(checkpoint).hexdigest(),
            "initial_shard_sha256": hashlib.sha256(input_shard).hexdigest(),
            "retry_shard_sha256": hashlib.sha256(retry_shard).hexdigest(),
            "trusted_shard_sha256": trusted_sha,
            "expected_checkpoint_sha256": hashlib.sha256(expected_checkpoint).hexdigest()}


def _job(lab, name, mode, claim, input_config, code_config, readonly=False, retries=1):
    pod_spec = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "runAsGroup": 65534, "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "reingest", "image": IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-B", "/code/reingest.py"],
            "env": [{"name": "MODE", "value": mode}],
            "securityContext": {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}},
            "volumeMounts": [{"name": "checkpoint", "mountPath": "/checkpoint",
                              "readOnly": readonly},
                             {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                             {"name": "code", "mountPath": "/code", "readOnly": True}]}],
        "volumes": [{"name": "checkpoint", "persistentVolumeClaim":
                     {"claimName": claim, "readOnly": readonly}},
                    {"name": "fixture", "configMap": {"name": input_config}},
                    {"name": "code", "configMap": {"name": code_config}}],
    }
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"backoffLimit": retries, "activeDeadlineSeconds": 90,
                 "completions": 1, "parallelism": 1,
                 "template": {"metadata": {"labels": _labels()}, "spec": pod_spec}},
    })


def _wait_job(lab, name, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {row.get("type") for row in job.get("status", {}).get("conditions", [])
                      if row.get("status") == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) == 1:
            pods = json.loads(lab.kubectl("get", "pods", "-l",
                f"batch.kubernetes.io/job-name={name}", "-o", "json").stdout)["items"]
            rows = []
            for pod in pods:
                metadata = pod.get("metadata", {})
                statuses = pod.get("status", {}).get("containerStatuses", [])
                terminated = statuses[0].get("state", {}).get("terminated", {}) if statuses else {}
                owner_ok = any(owner.get("kind") == "Job" and owner.get("controller") is True
                    and owner.get("uid") == job.get("metadata", {}).get("uid")
                    for owner in metadata.get("ownerReferences", []))
                logs = lab.kubectl("logs", f"pod/{metadata['name']}", allow_failure=True).stdout.strip()
                try:
                    record = json.loads(logs)
                except json.JSONDecodeError:
                    record = {}
                container = pod.get("spec", {}).get("containers", [{}])[0]
                mount = next((m for m in container.get("volumeMounts", [])
                              if m.get("name") == "checkpoint"), {})
                volume = next((v for v in pod.get("spec", {}).get("volumes", [])
                               if v.get("name") == "checkpoint"), {})
                rows.append({"uid": metadata.get("uid"), "phase": pod.get("status", {}).get("phase"),
                             "owner_uid_matches_job": owner_ok,
                             "exit_code": terminated.get("exitCode"), "record": record, "logs": logs,
                             "claim_name": volume.get("persistentVolumeClaim", {}).get("claimName"),
                             "claim_read_only": volume.get("persistentVolumeClaim", {}).get("readOnly", False),
                             "mount_read_only": mount.get("readOnly", False)})
            return terminal.pop(), job, rows
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    lab.block(f"training data re-ingestion Job {name} did not become terminal")


def _verifier_ok(state, job, pods, claim, expected_sha):
    return (state == "Complete" and job.get("spec", {}).get("backoffLimit") == 0
            and job.get("status", {}).get("succeeded") == 1 and len(pods) == 1
            and all(pod.get("owner_uid_matches_job") for pod in pods)
            and pods[0].get("exit_code") == 0 and pods[0].get("claim_name") == claim
            and pods[0].get("claim_read_only") is True and pods[0].get("mount_read_only") is True
            and pods[0].get("record", {}).get("event") == "independent-checkpoint-readback"
            and pods[0].get("record", {}).get("exact") is True
            and pods[0].get("record", {}).get("observed_sha256") == expected_sha)


def run(lab, fixture_item, pvc_module):
    checkpoint = _checkpoint_bytes(fixture_item)
    initial_sha = hashlib.sha256(checkpoint).hexdigest()
    shard_sha = hashlib.sha256(SHARD_APPROVED).hexdigest()
    if shard_sha != TRUSTED_SHARD_SHA256:
        lab.block("Approved inert training shard differs from its separately pinned source digest")
    expected_positive = json.dumps({"epoch": 13, "status": "continuation-verified",
                                    "previous_epoch": 12, "dataset_sha256": shard_sha},
                                   sort_keys=True, separators=(",", ":")).encode()
    correct = _configmap(lab, POSITIVE_INPUT, checkpoint, SHARD_APPROVED, SHARD_APPROVED,
                         shard_sha, expected_positive)
    corrupt = _configmap(lab, NEGATIVE_INPUT, checkpoint, SHARD_APPROVED, SHARD_CHANGED,
                         shard_sha, checkpoint)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": CODE_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
                "immutable": True, "data": {"reingest.py": SCRIPT}})
    code = json.loads(lab.kubectl("get", "configmap", CODE_CONFIG, "-o", "json").stdout)
    if code.get("immutable") is not True or code.get("data", {}).get("reingest.py") != SCRIPT:
        lab.block("Re-ingestion Job code ConfigMap is not the exact immutable fixture")

    positive_claim = "saf0901004-reingest-positive"
    negative_claim = "saf0901004-reingest-negative"
    pvc_module._pvc(lab, positive_claim)
    pvc_module._pvc(lab, negative_claim)
    positive_job = POSITIVE
    _job(lab, positive_job, "attempt", positive_claim, POSITIVE_INPUT, CODE_CONFIG)
    pos_state, pos_job, pos_pods = _wait_job(lab, positive_job)
    positive_verifier = POSITIVE + "-verify"
    _job(lab, positive_verifier, "verify", positive_claim, POSITIVE_INPUT, CODE_CONFIG,
         readonly=True, retries=0)
    pos_verify_state, pos_verify_job, pos_verify_pods = _wait_job(lab, positive_verifier)

    positive_pods_by_event = {pod.get("record", {}).get("event"): pod for pod in pos_pods}
    positive_first = positive_pods_by_event.get("initial-attempt-verified-and-checkpoint-persisted", {})
    positive_second = positive_pods_by_event.get("retry-data-reingestion-verified-and-checkpoint-continued", {})
    positive_order = (len(pos_pods) == 2 and positive_first.get("exit_code") == 42
                      and positive_second.get("exit_code") == 0
                      and positive_first.get("owner_uid_matches_job") is True
                      and positive_second.get("owner_uid_matches_job") is True
                      and positive_first.get("record", {}).get("attempt") == 1
                      and positive_second.get("record", {}).get("attempt") == 2
                      and positive_first.get("record", {}).get("dataset_sha256") == shard_sha
                      and positive_second.get("record", {}).get("dataset_sha256") == shard_sha
                      and positive_first.get("claim_name") == positive_claim
                      and positive_second.get("claim_name") == positive_claim)
    positive_readback = _verifier_ok(pos_verify_state, pos_verify_job, pos_verify_pods,
                                     positive_claim, hashlib.sha256(expected_positive).hexdigest())
    positive_ok = (pos_state == "Complete" and pos_job.get("spec", {}).get("backoffLimit") == 1
                   and pos_job.get("status", {}).get("succeeded") == 1
                   and pos_job.get("status", {}).get("failed") == 1
                   and positive_order and positive_readback
                   and correct["initial_checkpoint_sha256"] == initial_sha
                   and correct["initial_shard_sha256"] == shard_sha
                   and correct["retry_shard_sha256"] == shard_sha)
    positive_raw = {"job_condition": pos_state, "job_uid": pos_job.get("metadata", {}).get("uid"),
                    "backoff_limit": pos_job.get("spec", {}).get("backoffLimit"),
                    "failed": pos_job.get("status", {}).get("failed"),
                    "succeeded": pos_job.get("status", {}).get("succeeded"),
                    "pods": pos_pods, "verifier_job_condition": pos_verify_state,
                    "verifier_job_uid": pos_verify_job.get("metadata", {}).get("uid"),
                    "verifier_pods": pos_verify_pods, "fixture": correct,
                    "same_checkpoint_sha256": correct["initial_checkpoint_sha256"] == initial_sha,
                    "ordered_retry_reingestion": positive_order,
                    "independent_readback": positive_readback}
    lab.check("positive", "A real bounded Job retry re-ingests the approved shard before continuing the exact checkpoint",
              positive_ok,
              {"first_pod_failed_after_persisting_verified_checkpoint": positive_first.get("exit_code") == 42,
               "retry_pod_reingested_same_approved_shard": positive_second.get("record", {}).get("dataset_sha256") == shard_sha,
               "retry_continued_checkpoint": positive_second.get("record", {}).get("event") == "retry-data-reingestion-verified-and-checkpoint-continued",
               "independent_read_only_readback": positive_readback,
               "checkpoint_sha256": initial_sha,
               "data_shard_sha256": shard_sha})

    negative_job = NEGATIVE
    _job(lab, negative_job, "attempt", negative_claim, NEGATIVE_INPUT, CODE_CONFIG)
    neg_state, neg_job, neg_pods = _wait_job(lab, negative_job)
    negative_verifier = NEGATIVE + "-verify"
    _job(lab, negative_verifier, "verify", negative_claim, NEGATIVE_INPUT, CODE_CONFIG,
         readonly=True, retries=0)
    neg_verify_state, neg_verify_job, neg_verify_pods = _wait_job(lab, negative_verifier)
    negative_pods_by_event = {pod.get("record", {}).get("event"): pod for pod in neg_pods}
    negative_first = negative_pods_by_event.get("initial-attempt-verified-and-checkpoint-persisted", {})
    negative_second = negative_pods_by_event.get("retry-data-reingestion-digest-mismatch", {})
    negative_order = (len(neg_pods) == 2 and negative_first.get("exit_code") == 42
                      and negative_second.get("exit_code") == 24
                      and negative_first.get("owner_uid_matches_job") is True
                      and negative_second.get("owner_uid_matches_job") is True
                      and negative_first.get("record", {}).get("attempt") == 1
                      and negative_second.get("record", {}).get("attempt") == 2
                      and negative_first.get("record", {}).get("dataset_sha256") == shard_sha
                      and negative_second.get("record", {}).get("dataset_sha256") == corrupt["retry_shard_sha256"]
                      and negative_second.get("record", {}).get("expected_dataset_sha256") == shard_sha
                      and negative_second.get("record", {}).get("checkpoint_before_sha256") == initial_sha
                      and negative_second.get("record", {}).get("checkpoint_after_sha256") == initial_sha
                      and negative_first.get("claim_name") == negative_claim
                      and negative_second.get("claim_name") == negative_claim)
    negative_readback = _verifier_ok(neg_verify_state, neg_verify_job, neg_verify_pods,
                                     negative_claim, initial_sha)
    negative_ok = (neg_state == "Failed" and neg_job.get("spec", {}).get("backoffLimit") == 1
                   and neg_state == "Failed" and negative_order and negative_readback
                   and corrupt["initial_checkpoint_sha256"] == initial_sha
                   and corrupt["initial_shard_sha256"] == shard_sha
                   and corrupt["retry_shard_sha256"] != shard_sha)
    negative_raw = {"job_condition": neg_state, "job_uid": neg_job.get("metadata", {}).get("uid"),
                    "backoff_limit": neg_job.get("spec", {}).get("backoffLimit"),
                    "failed": neg_job.get("status", {}).get("failed"),
                    "succeeded": neg_job.get("status", {}).get("succeeded"),
                    "pods": neg_pods, "verifier_job_condition": neg_verify_state,
                    "verifier_job_uid": neg_verify_job.get("metadata", {}).get("uid"),
                    "verifier_pods": neg_verify_pods, "fixture": corrupt,
                    "same_checkpoint_sha256": corrupt["initial_checkpoint_sha256"] == initial_sha,
                    "ordered_retry_reingestion": negative_order,
                    "independent_readback": negative_readback}
    lab.check("red", "A changed harmless shard blocks retry continuation and leaves the persisted checkpoint unchanged",
              negative_ok,
              {"first_pod_persisted_verified_checkpoint": negative_first.get("exit_code") == 42,
               "retry_was_attempted_and_rejected": negative_second.get("record", {}).get("attempt") == 2
                   and negative_second.get("exit_code") == 24,
               "changed_shard_digest_rejected": negative_second.get("record", {}).get("dataset_sha256")
                   == corrupt["retry_shard_sha256"] != shard_sha,
               "checkpoint_before_equals_after": negative_second.get("record", {}).get("checkpoint_before_sha256")
                   == negative_second.get("record", {}).get("checkpoint_after_sha256") == initial_sha,
               "independent_read_only_readback_confirms_unchanged_checkpoint": negative_readback,
               "checkpoint_sha256": initial_sha,
               "approved_data_shard_sha256": shard_sha,
               "changed_retry_shard_sha256": corrupt["retry_shard_sha256"]})

    raw = {"scope": "two inert fixed data-shard Job paths, each with one bounded retry and an independent read-only checkpoint verifier",
           "initial_checkpoint_sha256": initial_sha, "approved_data_shard_sha256": shard_sha,
           "positive": positive_raw, "negative": negative_raw,
           "production_training_data_or_operator": False,
           "external_dataset_or_backup_service": False,
           "independent_failure_domain": False}
    (lab.evidence / "training-data-reingestion.raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return raw
