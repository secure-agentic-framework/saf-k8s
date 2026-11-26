"""Exercise governed external-model enrollment in a disposable OCI registry."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
REGISTRY = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
SCOPE = (
    "One disposable Kind v1.36.1 cluster runs a case-owned OCI Distribution 3.0.0 registry "
    "with a case-owned PVC backed by the disposable Kind node. A separate restricted scanner Job "
    "fetches fixed inert bytes from a case-owned HTTP source, checks their JSON structure and emits "
    "a digest-bound receipt consumed by the restricted intake Job. Red first proves direct registry "
    "publication accepts a model without lineage. Green "
    "rejects missing and unapproved lineage before upload, then admits an approved record bound "
    "to the exact OCI manifest digest. The record includes external origin, source digest, a "
    "fixture-only JSON structure scan result, fixture internalization date and approval decision. OCI "
    "attachment bytes and the approved subject are checked again after registry Pod replacement. "
    "A separate read-only observer Job fetches the approved publication and compares its lineage "
    "with the scanner receipt. The source, approval and date are fixture-only; this does not test "
    "scanner efficacy or independent scanner authority, human approval authenticity, authoritative "
    "time, registry authorization, real model formats, organizational policy or backup durability."
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


def _job(lab, source, name, verify=False, scanner_config=None):
    code_name = name + "-code"
    _configmap(lab, code_name, {"intake.py": source})
    mounts = [{"name": "code", "mountPath": "/app", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": code_name}}]
    if scanner_config:
        mounts.append({"name": "scan", "mountPath": "/scan", "readOnly": True})
        volumes.append({"name": "scan", "configMap": {"name": scanner_config}})
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
                                              "volumeMounts": mounts,
                                              "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                             "limits": {"cpu": "200m", "memory": "96Mi"}},
                                              "securityContext": {"allowPrivilegeEscalation": False,
                                                                   "readOnlyRootFilesystem": True,
                                                                   "capabilities": {"drop": ["ALL"]}}}],
                             "volumes": volumes}}}})
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


def _wait_app_pod(lab, selector, message):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        pods = json.loads(lab.kubectl("get", "pods", "-l", selector, "-o", "json").stdout)["items"]
        ready = [pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
                 and any(row.get("ready") for row in pod.get("status", {}).get("containerStatuses", []))]
        if ready:
            return ready[0]
        time.sleep(.5)
    lab.block(message)


def _supplement_job(lab, name, script_name, script, scanner_config=None):
    code_config = name + "-code"
    _configmap(lab, code_config, {script_name: script})
    mounts = [{"name": "code", "mountPath": "/app", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": code_config}}]
    if scanner_config:
        mounts.append({"name": "scan", "mountPath": "/scanner", "readOnly": True})
        volumes.append({"name": "scan", "configMap": {"name": scanner_config}})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60,
                         "template": {"spec": {
                             "restartPolicy": "Never", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                  "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "check", "image": PYTHON,
                                              "imagePullPolicy": "IfNotPresent",
                                              "command": ["python", "-B", "/app/" + script_name],
                                              "volumeMounts": mounts,
                                              "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                             "limits": {"cpu": "200m", "memory": "96Mi"}},
                                              "securityContext": {"allowPrivilegeEscalation": False,
                                                                   "readOnlyRootFilesystem": True,
                                                                   "capabilities": {"drop": ["ALL"]}}}],
                             "volumes": volumes}}}})
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {item["type"] for item in job.get("status", {}).get("conditions", [])
                      if item.get("status") == "True"}
        if "Failed" in conditions:
            lab.kubectl("logs", "job/" + name, allow_failure=True)
            lab.block(name + " failed")
        if "Complete" in conditions:
            return json.loads(lab.kubectl("logs", "job/" + name).stdout)
        time.sleep(.5)
    lab.block(name + " timed out")


def _run_independent_source_scan(lab):
    fixture = (HERE / "source_model.json").read_text()
    source = (HERE / "source_server.py").read_text()
    _configmap(lab, "model-source-files", {"model.json": fixture, "source_server.py": source})
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "model-source"},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "model-source"}},
                         "template": {"metadata": {"labels": {"app": "model-source"}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                                    "seccompProfile": {"type": "RuntimeDefault"}},
                                               "containers": [{"name": "source", "image": PYTHON,
                                                               "imagePullPolicy": "IfNotPresent",
                                                               "command": ["python", "-B", "/fixture/source_server.py"],
                                                               "ports": [{"containerPort": 8080}],
                                                               "readinessProbe": {"httpGet": {"path": "/model.json", "port": 8080},
                                                                                  "periodSeconds": 1},
                                                               "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                                                                 "readOnly": True}],
                                                               "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                                              "limits": {"cpu": "100m", "memory": "48Mi"}},
                                                               "securityContext": {"allowPrivilegeEscalation": False,
                                                                                    "readOnlyRootFilesystem": True,
                                                                                    "capabilities": {"drop": ["ALL"]}}}],
                                               "volumes": [{"name": "fixture", "configMap": {"name": "model-source-files"}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "model-source"},
                "spec": {"selector": {"app": "model-source"}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    _wait_app_pod(lab, "app=model-source", "Case-owned inert source did not become Ready")
    scanner = _supplement_job(lab, "independent-model-scanner", "scanner_job.py",
                              (HERE / "scanner_job.py").read_text())
    return scanner


def _observe_published_lineage(lab):
    return _supplement_job(lab, "independent-lineage-observer", "publication_observer.py",
                           (HERE / "publication_observer.py").read_text(),
                           scanner_config="independent-scan-receipt")


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
    scanner = _run_independent_source_scan(lab)
    scanner_config = "independent-scan-receipt"
    _configmap(lab, scanner_config, {"scan.json": json.dumps(scanner, sort_keys=True, separators=(",", ":"))})
    source = (HERE / "intake.py").read_text()
    result = _job(lab, source, "model-intake", scanner_config=scanner_config)
    old_uid = first["metadata"]["uid"]
    lab.kubectl("delete", "pod", first["metadata"]["name"], "--wait=true", timeout=60)
    second = _wait_pod(lab)
    if second["metadata"]["uid"] == old_uid:
        lab.block("Registry Pod was not replaced for the persistence check")
    persisted = _job(lab, source, "model-intake-recheck", verify=True, scanner_config=scanner_config)
    baseline = {key: result[key] for key in ("approved_model_retrievable", "approved_lineage_retrievable",
                                             "source_digest", "subject_digest", "lineage_digest")}
    result["persisted_after_replacement"] = persisted == baseline
    publication_observation = _observe_published_lineage(lab)
    (lab.evidence / "independent-source-scan.json").write_text(json.dumps(
        {"scanner_receipt": scanner, "publication_observation": publication_observation}, indent=2) + "\n")
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
    expected = {"external_origin": "http://model-source:8080/model.json",
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
    expected_source_digest = "sha256:" + hashlib.sha256((HERE / "source_model.json").read_bytes()).hexdigest()
    scan_result = scanner.get("scan_result", {})
    lab.check("positive", "A separate bounded scanner Job reads the case-owned source bytes and emits their digest",
              scanner == {"scan_result": {"scanner": "fixture-json-structure-v1", "status": "pass",
                                           "source_digest": expected_source_digest},
                          "source_bytes_bounded": True},
              {"scanner": scan_result.get("scanner"), "status": scan_result.get("status"),
               "source_digest_matches_fixture": scan_result.get("source_digest") == expected_source_digest,
               "source_bytes_bounded": scanner.get("source_bytes_bounded") is True})
    predicates = {"scanner_receipt_passed", "source_digest_matches_internal_layer",
                  "lineage_scan_matches_scanner_receipt", "lineage_source_digest_matches_scanner",
                  "lineage_subject_matches_approved_manifest", "approved_tag_and_subject_readable"}
    lab.check("positive", "An independent read-only Job reads the approved OCI publication and confirms digest-bound scanner lineage",
              set(publication_observation) == predicates and all(publication_observation.values()),
              publication_observation)
