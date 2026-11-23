"""Exercise governed external-model enrollment in a disposable OCI registry."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
REGISTRY = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
SCOPE = (
    "One disposable Kind v1.36.1 cluster runs a case-owned OCI Distribution 3.0.0 registry "
    "with a case-owned PVC backed by the disposable Kind node. A restricted Python intake Job "
    "uses an enforced enrollment function over the registry HTTP API for inert synthetic model "
    "bytes. Red first proves direct registry publication accepts a model without lineage. Green "
    "rejects missing and unapproved lineage before upload, then admits an approved record bound "
    "to the exact OCI manifest digest. The record includes external origin, source digest, a "
    "fixture-only JSON structure scan result, fixture internalization date and approval decision. OCI "
    "attachment bytes and the approved subject are checked again after registry Pod replacement. "
    "This does not test scanner efficacy, human approval authenticity, real model formats, "
    "production identity/access controls, organizational registry policy or backup durability."
)


def _configmap(lab, name, scripts):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": scripts})


def _wait_pod(lab):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        pods = json.loads(lab.kubectl("get", "pods", "-l", "app=model-registry", "-o", "json").stdout)["items"]
        ready = [pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
                 and any(row.get("ready") for row in pod.get("status", {}).get("containerStatuses", []))]
        if ready:
            return ready[0]
        time.sleep(1)
    lab.block("Case-owned registry did not become Ready")


def _job(lab, source, name, verify=False):
    code_name = name + "-code"
    _configmap(lab, code_name, {"intake.py": source})
    command = ["python", "-B", "/app/intake.py"] + (["verify"] if verify else [])
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                         "template": {"spec": {
                             "restartPolicy": "Never", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                  "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "intake", "image": PYTHON,
                                              "imagePullPolicy": "IfNotPresent",
                                              "command": command,
                                              "volumeMounts": [{"name": "code", "mountPath": "/app", "readOnly": True}],
                                              "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                             "limits": {"cpu": "200m", "memory": "96Mi"}},
                                              "securityContext": {"allowPrivilegeEscalation": False,
                                                                   "readOnlyRootFilesystem": True,
                                                                   "capabilities": {"drop": ["ALL"]}}}],
                             "volumes": [{"name": "code", "configMap": {"name": code_name}}]}}}})
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {item["type"] for item in job.get("status", {}).get("conditions", [])
                      if item.get("status") == "True"}
        if "Failed" in conditions:
            lab.kubectl("logs", "job/" + name, allow_failure=True)
            lab.block("Intake Job failed outside an expected metadata rejection")
        if "Complete" in conditions:
            return json.loads(lab.kubectl("logs", "job/" + name).stdout)
        time.sleep(.5)
    lab.block("Intake Job timed out")


def run(lab):
    pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "model-registry-data"},
          "spec": {"capacity": {"storage": "64Mi"}, "accessModes": ["ReadWriteOnce"],
                   "persistentVolumeReclaimPolicy": "Delete", "storageClassName": "",
                   "hostPath": {"path": "/var/lib/saf-0905-059-registry", "type": "DirectoryOrCreate"}}}
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "model-registry-data"},
           "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "",
                    "volumeName": pv["metadata"]["name"], "resources": {"requests": {"storage": "64Mi"}}}}
    lab.create(pv)
    lab.create(pvc)
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "model-registry"},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "model-registry"}},
                         "template": {"metadata": {"labels": {"app": "model-registry"}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "containers": [{"name": "registry", "image": REGISTRY,
                                                               "ports": [{"containerPort": 5000}],
                                                               "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000},
                                                                                  "periodSeconds": 1},
                                                               "resources": {"requests": {"cpu": "30m", "memory": "64Mi"},
                                                                              "limits": {"cpu": "300m", "memory": "256Mi"}},
                                                               "volumeMounts": [{"name": "data", "mountPath": "/var/lib/registry"}]}],
                                               "volumes": [{"name": "data", "persistentVolumeClaim":
                                                            {"claimName": "model-registry-data"}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "model-registry"},
                "spec": {"selector": {"app": "model-registry"}, "ports": [{"port": 5000}]}})
    first = _wait_pod(lab)
    source = (HERE / "intake.py").read_text()
    result = _job(lab, source, "model-intake")
    old_uid = first["metadata"]["uid"]
    lab.kubectl("delete", "pod", first["metadata"]["name"], "--wait=true", timeout=60)
    second = _wait_pod(lab)
    if second["metadata"]["uid"] == old_uid:
        lab.block("Registry Pod was not replaced for the persistence check")
    persisted = _job(lab, source, "model-intake-recheck", verify=True)
    baseline = {key: result[key] for key in ("approved_model_retrievable", "approved_lineage_retrievable",
                                             "source_digest", "subject_digest", "lineage_digest")}
    result["persisted_after_replacement"] = persisted == baseline
    (lab.evidence / "external-origin-enrollment.json").write_text(json.dumps(
        {"before_replacement": result, "after_replacement": persisted,
         "registry_pod_uids": [old_uid, second["metadata"]["uid"]]}, indent=2) + "\n")
    lab.check("red", "Direct OCI registry publication accepts an inert model before the enrollment gate",
              result["red_registry_status"] == 201 and result["red_has_no_lineage"],
              {"manifest_put_status": result["red_registry_status"], "lineage_present": False})
    lab.check("green", "Enrollment rejects missing and unapproved metadata before registry publication",
              result["rejected"] == {"missing": "metadata_incomplete", "unapproved": "decision_not_approved",
                                      "wrong-scan-result": "scan_result_mismatch"}
              and result["rejected_enrollment_tags_absent"],
              {"missing": result["rejected"]["missing"], "unapproved": result["rejected"]["unapproved"],
               "wrong_scan_result": result["rejected"]["wrong-scan-result"],
               "rejected_enrollment_tags_absent": result["rejected_enrollment_tags_absent"]})
    expected = {"external_origin": "https://source.example.invalid/inert-model-fixture",
                "source_digest": result["source_digest"],
                "scan_result": {"scanner": "fixture-json-structure-v1", "status": "pass", "source_digest": result["source_digest"]},
                "internalization_date": "2026-04-17", "date_kind": "fixture-date",
                "decision": "approved", "decision_ref": "fixture-approval-001",
                "subject_digest": result["subject_digest"]}
    lab.check("green", "Approved lineage is attached to the exact OCI subject and survives Pod replacement",
              result["lineage"] == expected and result["persisted_after_replacement"],
              {"fields_present": sorted(result["lineage"]), "subject_matches": True,
               "fixture_structure_scan_status": "pass", "date_kind": "fixture-date",
               "persistent_readback": result["persisted_after_replacement"]})
    lab.check("positive", "The approved external model is retrievable with its complete lineage record",
              result["approved_model_retrievable"] and result["approved_lineage_retrievable"],
              {"model_retrievable": result["approved_model_retrievable"],
               "lineage_retrievable": result["approved_lineage_retrievable"],
               "subject_digest": result["subject_digest"]})
