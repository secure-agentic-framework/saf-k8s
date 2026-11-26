"""Case-owned PVC checkpoint backup and fresh-volume restore witness."""
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
PVC_NAMES = {
    "source": "saf0901004-checkpoint-source",
    "backup": "saf0901004-checkpoint-backup",
    "restore": "saf0901004-checkpoint-restore",
}
JOB_NAMES = {
    "backup": "saf0901004-pvc-backup",
    "restore": "saf0901004-pvc-restore",
    "verify": "saf0901004-pvc-verify",
}
SCRIPT = r'''import hashlib,json,shutil,sys
from pathlib import Path
mode=sys.argv[1]
payload=Path("/fixture/checkpoint.json").read_bytes()
expected=Path("/fixture/expected.sha256").read_text().strip()
def digest(value): return hashlib.sha256(value).hexdigest()
out={"mode":mode,"expected_digest_matches_fixture":digest(payload)==expected}
if mode=="backup":
    source=Path("/source/checkpoint.json"); backup=Path("/backup/checkpoint.json")
    source.write_bytes(payload)
    source_bytes=source.read_bytes()
    shutil.copyfile(source,backup)
    backup_bytes=backup.read_bytes()
    out.update(source_digest=digest(source_bytes),backup_digest=digest(backup_bytes),
      source_size=len(source_bytes),backup_size=len(backup_bytes),source_exact=source_bytes==payload,
      backup_exact=backup_bytes==payload,source_backup_equal=source_bytes==backup_bytes)
    ok=(out["expected_digest_matches_fixture"] and out["source_digest"]==expected
        and out["backup_digest"]==expected and out["source_exact"] and out["backup_exact"]
        and out["source_backup_equal"] and out["source_size"]==out["backup_size"])
elif mode=="restore":
    backup=Path("/backup/checkpoint.json"); restored=Path("/restore/checkpoint.json")
    backup_bytes=backup.read_bytes()
    shutil.copyfile(backup,restored)
    restored_bytes=restored.read_bytes()
    out.update(backup_digest=digest(backup_bytes),restored_digest=digest(restored_bytes),
      backup_size=len(backup_bytes),restored_size=len(restored_bytes),
      backup_exact=backup_bytes==payload,restored_exact=restored_bytes==payload,
      backup_restore_equal=backup_bytes==restored_bytes)
    ok=(out["expected_digest_matches_fixture"] and out["backup_digest"]==expected
        and out["restored_digest"]==expected and out["backup_exact"] and out["restored_exact"]
        and out["backup_restore_equal"] and out["backup_size"]==out["restored_size"])
elif mode=="verify":
    backup_bytes=Path("/backup/checkpoint.json").read_bytes()
    restored_bytes=Path("/restore/checkpoint.json").read_bytes()
    out.update(backup_digest=digest(backup_bytes),restored_digest=digest(restored_bytes),
      backup_size=len(backup_bytes),restored_size=len(restored_bytes),
      backup_exact=backup_bytes==payload,restored_exact=restored_bytes==payload,
      byte_integrity_equal=backup_bytes==restored_bytes,
      checkpoint_json_valid=False)
    try:
      value=json.loads(restored_bytes)
      out["checkpoint_json_valid"]=(value=={"epoch":12,"status":"approved-fixture-b"})
    except (ValueError,TypeError): pass
    ok=(out["expected_digest_matches_fixture"] and out["backup_digest"]==expected
        and out["restored_digest"]==expected and out["backup_exact"] and out["restored_exact"]
        and out["byte_integrity_equal"] and out["checkpoint_json_valid"]
        and out["backup_size"]==out["restored_size"])
else:
    out.update(mode_valid=False); ok=False
out["result"]="verified" if ok else "integrity-failed"
print(json.dumps(out,sort_keys=True))
raise SystemExit(0 if ok else 23)
'''


def _owned_labels():
    return {LABEL_CONTROL: "SAF-K8S-0901-004", LABEL_FIXTURE: "true"}


def _create(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _pvc(lab, name):
    _create(lab, {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _owned_labels()},
        "spec": {"accessModes": ["ReadWriteOnce"],
                 "resources": {"requests": {"storage": "64Mi"}}},
    })


def _job(lab, operation, mounts, volumes, input_config):
    name = JOB_NAMES[operation]
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _owned_labels()},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "template": {"metadata": {"labels": _owned_labels()}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "runAsGroup": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{
                         "name": "checkpoint", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                         "command": ["python", "-B", "/code/pvc_checkpoint.py", operation],
                         "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                         "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                         "volumeMounts": mounts,
                     }],
                     "volumes": [*volumes,
                                 {"name": "fixture", "configMap": {"name": input_config}},
                                 {"name": "code", "configMap": {"name": "saf0901004-pvc-code"}}],
                 }}},
    })


def _job_result(lab, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {row.get("type") for row in job.get("status", {}).get("conditions", [])
                      if row.get("status") == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) == 1:
            pods = json.loads(lab.kubectl(
                "get", "pods", "-l", f"batch.kubernetes.io/job-name={name}", "-o", "json").stdout)["items"]
            log = lab.kubectl("logs", f"job/{name}", allow_failure=True).stdout.strip()
            try:
                record = json.loads(log)
            except json.JSONDecodeError:
                record = {}
            return terminal.pop(), job, pods, record
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    lab.block(f"PVC checkpoint Job {name} did not reach a terminal condition")


def _claim_identity(lab, claim_name):
    claim = json.loads(lab.kubectl("get", "pvc", claim_name, "-o", "json").stdout)
    metadata = claim.get("metadata", {})
    return {"name": metadata.get("name"), "uid": metadata.get("uid"),
            "namespace": metadata.get("namespace"), "labels": metadata.get("labels", {}),
            "phase": claim.get("status", {}).get("phase"),
            "pv_name": claim.get("spec", {}).get("volumeName"),
            "storage_class": claim.get("spec", {}).get("storageClassName")}


def run(lab, fixture_item):
    checkpoint = fixture_item["object"]["data"]["checkpoint.json"].encode()
    expected_digest = hashlib.sha256(checkpoint).hexdigest()
    input_config = "saf0901004-pvc-input"
    code_config = "saf0901004-pvc-code"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": input_config, "namespace": NAMESPACE, "labels": _owned_labels()},
                "immutable": True,
                "data": {"checkpoint.json": checkpoint.decode(), "expected.sha256": expected_digest}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": code_config, "namespace": NAMESPACE, "labels": _owned_labels()},
                "immutable": True, "data": {"pvc_checkpoint.py": SCRIPT}})

    source_name, backup_name = PVC_NAMES["source"], PVC_NAMES["backup"]
    _pvc(lab, source_name)
    _pvc(lab, backup_name)
    _job(lab, "backup", [
        {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
        {"name": "code", "mountPath": "/code", "readOnly": True},
        {"name": "source", "mountPath": "/source"},
        {"name": "backup", "mountPath": "/backup"},
    ], [
        {"name": "source", "persistentVolumeClaim": {"claimName": source_name}},
        {"name": "backup", "persistentVolumeClaim": {"claimName": backup_name}},
    ], input_config)
    backup_state, backup_job, backup_pods, backup_result = _job_result(lab, JOB_NAMES["backup"])

    # The restore claim is created only after the source->backup copy has completed.
    restore_name = PVC_NAMES["restore"]
    _pvc(lab, restore_name)
    _job(lab, "restore", [
        {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
        {"name": "code", "mountPath": "/code", "readOnly": True},
        {"name": "backup", "mountPath": "/backup", "readOnly": True},
        {"name": "restore", "mountPath": "/restore"},
    ], [
        {"name": "backup", "persistentVolumeClaim": {"claimName": backup_name, "readOnly": True}},
        {"name": "restore", "persistentVolumeClaim": {"claimName": restore_name}},
    ], input_config)
    restore_state, restore_job, restore_pods, restore_result = _job_result(lab, JOB_NAMES["restore"])
    _job(lab, "verify", [
        {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
        {"name": "code", "mountPath": "/code", "readOnly": True},
        {"name": "backup", "mountPath": "/backup", "readOnly": True},
        {"name": "restore", "mountPath": "/restore", "readOnly": True},
    ], [
        {"name": "backup", "persistentVolumeClaim": {"claimName": backup_name, "readOnly": True}},
        {"name": "restore", "persistentVolumeClaim": {"claimName": restore_name, "readOnly": True}},
    ], input_config)
    verify_state, verify_job, verify_pods, verify_result = _job_result(lab, JOB_NAMES["verify"])

    identities = {key: _claim_identity(lab, value) for key, value in PVC_NAMES.items()}
    uids = [row.get("uid") for row in identities.values()]
    pv_names = [row.get("pv_name") for row in identities.values()]
    identity_ok = (all(row.get("namespace") == NAMESPACE and row.get("phase") == "Bound"
                       and row.get("labels") == _owned_labels()
                       and row.get("uid") and row.get("pv_name") for row in identities.values())
                   and len(set(uids)) == 3 and len(set(pv_names)) == 3)
    jobs_ok = all(state == "Complete" and job.get("spec", {}).get("backoffLimit") == 0
                  and job.get("status", {}).get("succeeded") == 1 and len(pods) == 1
                  for state, job, pods in ((backup_state, backup_job, backup_pods),
                                           (restore_state, restore_job, restore_pods),
                                           (verify_state, verify_job, verify_pods)))
    expected_mounts = {
        "backup": {"source": source_name, "backup": backup_name},
        "restore": {"backup": backup_name, "restore": restore_name},
        "verify": {"backup": backup_name, "restore": restore_name},
    }
    observed_mounts = {}
    for operation, job in (("backup", backup_job), ("restore", restore_job), ("verify", verify_job)):
        spec = job.get("spec", {}).get("template", {}).get("spec", {})
        observed_mounts[operation] = {
            volume["name"]: volume.get("persistentVolumeClaim", {}).get("claimName")
            for volume in spec.get("volumes", []) if "persistentVolumeClaim" in volume
        }
    mount_mapping_ok = observed_mounts == expected_mounts
    content_ok = (
        backup_result.get("result") == "verified" and backup_result.get("source_digest") == expected_digest
        and backup_result.get("backup_digest") == expected_digest and backup_result.get("source_backup_equal")
        and restore_result.get("result") == "verified" and restore_result.get("backup_digest") == expected_digest
        and restore_result.get("restored_digest") == expected_digest and restore_result.get("backup_restore_equal")
        and verify_result.get("result") == "verified" and verify_result.get("backup_digest") == expected_digest
        and verify_result.get("restored_digest") == expected_digest and verify_result.get("backup_exact")
        and verify_result.get("restored_exact") and verify_result.get("byte_integrity_equal")
        and verify_result.get("checkpoint_json_valid") and backup_result.get("source_size") == verify_result.get("restored_size"))
    passed = identity_ok and jobs_ok and mount_mapping_ok and content_ok
    evidence = {"scope": "case-owned synthetic checkpoint bytes on three PVCs in one disposable cluster",
                "checkpoint_sha256": expected_digest, "checkpoint_size": len(checkpoint),
                "pvc_identities": identities,
                "restore_claim_created_after_backup_job_completed": backup_state == "Complete",
                "job_claim_mounts": observed_mounts,
                "expected_job_claim_mounts": expected_mounts,
                "job_claim_mounts_exact": mount_mapping_ok,
                "jobs": {"backup": {"condition": backup_state, "backoff_limit": backup_job.get("spec", {}).get("backoffLimit"),
                                     "pod_count": len(backup_pods), "observation": backup_result},
                         "restore": {"condition": restore_state, "backoff_limit": restore_job.get("spec", {}).get("backoffLimit"),
                                     "pod_count": len(restore_pods), "observation": restore_result},
                         "independent_readback": {"condition": verify_state, "backoff_limit": verify_job.get("spec", {}).get("backoffLimit"),
                                                  "pod_count": len(verify_pods), "observation": verify_result}},
                "external_storage_or_backup_service": False, "independent_failure_domain": False,
                "production_checkpoint_or_model": False}
    (lab.evidence / "checkpoint-pvc-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
    normalized = {key: value for key, value in evidence.items() if key != "pvc_identities"}
    normalized["three_distinct_bound_pvc_and_pv_identities"] = identity_ok
    lab.check("recovery", "A benign checkpoint is copied between distinct source and backup PVCs and restored/read back on a fresh third PVC",
              passed, normalized)
    return evidence
