"""Bounded Job retry and checkpoint continuation on one case-owned PVC."""
import hashlib
import json
import time


NAMESPACE = "saf-test"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
PVC_NAME = "saf0901004-retry-checkpoint"
JOB_NAME = "saf0901004-retry-continuation"
VERIFY_JOB_NAME = "saf0901004-retry-independent-verify"
INPUT_CONFIG = "saf0901004-retry-input"
CODE_CONFIG = "saf0901004-retry-code"
LABEL_CONTROL = "saf-k8s.example/control"
LABEL_FIXTURE = "saf-k8s.example/fixture"
SCRIPT = r'''import hashlib,json,os
from pathlib import Path
root=Path("/checkpoint")
initial=Path("/fixture/initial.json").read_bytes()
expected=Path("/fixture/expected.json").read_bytes()
state=root/"state.json"
def digest(b): return hashlib.sha256(b).hexdigest()
if os.environ["MODE"]=="attempt":
    if not state.exists():
        tmp=root/"state.tmp"
        tmp.write_bytes(initial)
        os.replace(tmp,state)
        print(json.dumps({"event":"checkpoint-written-before-bounded-failure",
          "checkpoint_sha256":digest(initial),"bytes":len(initial)},sort_keys=True))
        raise SystemExit(42)
    prior=state.read_bytes()
    if prior!=initial or digest(prior)!=os.environ["INITIAL_SHA256"]:
        print(json.dumps({"event":"checkpoint-integrity-failed","checkpoint_sha256":digest(prior)},sort_keys=True))
        raise SystemExit(23)
    previous_epoch=json.loads(prior)["epoch"]
    continued=json.dumps({"epoch":previous_epoch+1,"status":"continuation-verified",
      "previous_epoch":previous_epoch},sort_keys=True,separators=(",",":")).encode()
    tmp=root/"state.tmp"
    tmp.write_bytes(continued)
    os.replace(tmp,state)
    print(json.dumps({"event":"checkpoint-verified-and-continuation-completed",
      "prior_checkpoint_sha256":digest(prior),"result_sha256":digest(continued),
      "result_bytes":len(continued)},sort_keys=True))
    raise SystemExit(0)
actual=state.read_bytes() if state.exists() else b""
valid=(actual==expected and digest(actual)==os.environ["EXPECTED_SHA256"])
print(json.dumps({"event":"independent-pvc-readback","expected_sha256":os.environ["EXPECTED_SHA256"],
  "observed_sha256":digest(actual),"bytes":len(actual),"exact":valid},sort_keys=True))
raise SystemExit(0 if valid else 24)
'''


def _labels():
    return {LABEL_CONTROL: "SAF-K8S-0901-004", LABEL_FIXTURE: "true"}


def _job(lab, name, mode, initial_sha, expected_sha, retry):
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"backoffLimit": 1 if retry else 0,
                 "activeDeadlineSeconds": 90, "completions": 1, "parallelism": 1,
                 "template": {"metadata": {"labels": _labels()}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "runAsGroup": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "checkpoint", "image": IMAGE,
                         "imagePullPolicy": "IfNotPresent",
                         "command": ["python", "-B", "/code/retry_checkpoint.py"],
                         "env": [{"name": "MODE", "value": mode},
                                 {"name": "INITIAL_SHA256", "value": initial_sha},
                                 {"name": "EXPECTED_SHA256", "value": expected_sha}],
                         "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                         "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                         "volumeMounts": [{"name": "checkpoint", "mountPath": "/checkpoint",
                                           "readOnly": mode == "verify"},
                                           {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                           {"name": "code", "mountPath": "/code", "readOnly": True}]}],
                     "volumes": [{"name": "checkpoint", "persistentVolumeClaim":
                                  {"claimName": PVC_NAME, "readOnly": mode == "verify"}},
                                 {"name": "fixture", "configMap": {"name": INPUT_CONFIG}},
                                 {"name": "code", "configMap": {"name": CODE_CONFIG}}],
                 }}}})


def _wait_job(lab, name, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {c.get("type") for c in job.get("status", {}).get("conditions", [])
                      if c.get("status") == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) == 1:
            pods = json.loads(lab.kubectl("get", "pods", "-l",
                f"batch.kubernetes.io/job-name={name}", "-o", "json").stdout)["items"]
            rows = []
            for pod in pods:
                meta = pod.get("metadata", {})
                owner_ok = any(o.get("kind") == "Job" and o.get("uid") == job.get("metadata", {}).get("uid")
                               and o.get("controller") is True for o in meta.get("ownerReferences", []))
                log = lab.kubectl("logs", f"pod/{meta['name']}", allow_failure=True).stdout.strip()
                try:
                    record = json.loads(log)
                except json.JSONDecodeError:
                    record = {}
                pod_status = pod.get("status", {})
                container_status, = pod_status.get("containerStatuses", [{}])
                container, = pod["spec"]["containers"]
                mount = next(v for v in container["volumeMounts"] if v["name"] == "checkpoint")
                volume = next(v for v in pod["spec"]["volumes"] if v["name"] == "checkpoint")
                rows.append({"name": meta.get("name"), "uid": meta.get("uid"),
                             "phase": pod_status.get("phase"), "owner_uid_matches_job": owner_ok,
                             "exit_code": container_status.get("state", {}).get("terminated", {}).get("exitCode"),
                             "claim_name": volume["persistentVolumeClaim"]["claimName"],
                             "claim_read_only": volume["persistentVolumeClaim"].get("readOnly", False),
                             "mount_read_only": mount.get("readOnly", False),
                    "logs": log, "record": record})
            return terminal.pop(), job, rows
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    lab.block(f"bounded retry checkpoint Job {name} did not become terminal")


def run(lab, fixture_item, pvc_module):
    initial = fixture_item["object"]["data"]["checkpoint.json"].encode()
    initial_value = json.loads(initial)
    if initial_value != {"epoch": 12, "status": "approved-fixture-b"}:
        lab.block("retry fixture is outside the exact inert checkpoint allowlist")
    expected = json.dumps({"epoch": 13, "status": "continuation-verified",
                           "previous_epoch": 12}, sort_keys=True, separators=(",", ":")).encode()
    initial_sha, expected_sha = hashlib.sha256(initial).hexdigest(), hashlib.sha256(expected).hexdigest()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": INPUT_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True, "data": {"initial.json": initial.decode(), "expected.json": expected.decode()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CODE_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True, "data": {"retry_checkpoint.py": SCRIPT}})
    pvc_module._pvc(lab, PVC_NAME)
    _job(lab, JOB_NAME, "attempt", initial_sha, expected_sha, True)
    retry_state, retry_job, retry_pods = _wait_job(lab, JOB_NAME)
    _job(lab, VERIFY_JOB_NAME, "verify", initial_sha, expected_sha, False)
    verify_state, verify_job, verify_pods = _wait_job(lab, VERIFY_JOB_NAME)
    claim = json.loads(lab.kubectl("get", "pvc", PVC_NAME, "-o", "json").stdout)
    claim_meta = claim.get("metadata", {})
    claim_uid = claim_meta.get("uid")
    pv_name = claim.get("spec", {}).get("volumeName")
    volume = json.loads(lab.kubectl("get", "pv", pv_name, "-o", "json").stdout)
    volume_ref = volume.get("spec", {}).get("claimRef", {})
    expected_exits = {(p.get("phase"), p.get("exit_code")) for p in retry_pods} == {
        ("Failed", 42), ("Succeeded", 0)}
    retry_ids = [p.get("uid") for p in retry_pods]
    retry_identity_ok = (retry_state == "Complete" and retry_job.get("spec", {}).get("backoffLimit") == 1
        and retry_job.get("status", {}).get("succeeded") == 1
        and retry_job.get("status", {}).get("failed") == 1
        and len(retry_pods) == 2 and len(set(retry_ids)) == 2 and all(retry_ids)
        and all(p.get("owner_uid_matches_job") for p in retry_pods) and expected_exits)
    first_record = next((p["record"] for p in retry_pods if p.get("phase") == "Failed"), {})
    second_record = next((p["record"] for p in retry_pods if p.get("phase") == "Succeeded"), {})
    continuation_ok = (first_record.get("event") == "checkpoint-written-before-bounded-failure"
        and first_record.get("checkpoint_sha256") == initial_sha
        and second_record.get("event") == "checkpoint-verified-and-continuation-completed"
        and second_record.get("prior_checkpoint_sha256") == initial_sha
        and second_record.get("result_sha256") == expected_sha)
    verifier_ok = (verify_state == "Complete" and verify_job.get("spec", {}).get("backoffLimit") == 0
        and verify_job.get("status", {}).get("succeeded") == 1 and len(verify_pods) == 1
        and all(p.get("owner_uid_matches_job") for p in verify_pods)
        and verify_pods[0]["exit_code"] == 0 and verify_pods[0]["claim_read_only"]
        and verify_pods[0]["mount_read_only"]
        and verify_pods[0].get("record", {}).get("exact") is True
        and verify_pods[0].get("record", {}).get("observed_sha256") == expected_sha)
    retry_claims = [v.get("persistentVolumeClaim", {}).get("claimName") for v in
        retry_job.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
        if v.get("persistentVolumeClaim")]
    verify_claims = [v.get("persistentVolumeClaim", {}).get("claimName") for v in
        verify_job.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
        if v.get("persistentVolumeClaim")]
    same_claim_ok = (retry_claims == [PVC_NAME] and verify_claims == [PVC_NAME]
                     and all(p["claim_name"] == PVC_NAME for p in [*retry_pods, *verify_pods]))
    pvc_ok = (claim_meta.get("namespace") == NAMESPACE and claim_meta.get("labels") == _labels()
        and claim.get("status", {}).get("phase") == "Bound" and bool(claim_uid)
        and volume_ref.get("uid") == claim_uid and volume_ref.get("namespace") == NAMESPACE
        and volume_ref.get("name") == PVC_NAME)
    passed = retry_identity_ok and continuation_ok and verifier_ok and same_claim_ok and pvc_ok
    raw = {"scope": "one synthetic checkpoint, one owned PVC, one bounded Job retry, and one independent read-only verifier",
        "checkpoint_sha256": initial_sha, "continued_result_sha256": expected_sha,
        "pvc": {"name": PVC_NAME, "uid": claim_uid, "phase": claim.get("status", {}).get("phase"),
                "volume_name": pv_name, "volume_uid": volume["metadata"]["uid"],
                "volume_claim_uid": volume_ref.get("uid"), "labels": claim_meta.get("labels")},
        "retry_job": {"uid": retry_job.get("metadata", {}).get("uid"), "condition": retry_state,
            "backoff_limit": retry_job.get("spec", {}).get("backoffLimit"),
            "failed": retry_job.get("status", {}).get("failed"), "succeeded": retry_job.get("status", {}).get("succeeded"),
            "pods": retry_pods},
        "verifier_job": {"uid": verify_job.get("metadata", {}).get("uid"), "condition": verify_state,
            "pods": verify_pods},
        "observations": {"two_distinct_retry_pods_owned_by_same_job": retry_identity_ok,
            "second_attempt_verified_and_continued_same_checkpoint": continuation_ok,
            "independent_read_only_job_verified_final_pvc_bytes": verifier_ok,
            "retry_and_verifier_jobs_mount_same_claim": same_claim_ok,
            "owned_bound_pvc": pvc_ok},
        "training_framework_or_operator": False, "production_backup_or_failure_domain": False}
    (lab.evidence / "job-retry-continuation-raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    normalized = {"two_distinct_retry_pods_owned_by_same_job": retry_identity_ok,
        "second_attempt_verified_and_continued_same_checkpoint": continuation_ok,
        "independent_read_only_job_verified_final_pvc_bytes": verifier_ok,
        "retry_and_verifier_jobs_mount_same_claim": same_claim_ok,
        "case_owned_bound_pvc": pvc_ok}
    lab.check("recovery", "A bounded Kubernetes Job retry verifies the persisted checkpoint on a new Pod, continues it, and an independent Job verifies the same PVC result", passed, normalized)
    return raw
