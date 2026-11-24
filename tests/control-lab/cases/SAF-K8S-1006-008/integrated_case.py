"""Optional PW.3.1 integrity-before-use and feature-publication fixture."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE.parent
NS = "saf-test"
CODE = "saf-1006-008-integrated-code"
MANIFEST = "saf-1006-008-integrated-manifest"
CLAIM = "saf-1006-008-integrated-state"
SCENARIOS = ("wrong-bytes", "missing-partition", "approved-clean")
def _job(name, command, image, *, reader=False):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NS,
                     "labels": {"saf.synthetic": "true", "saf.case": "1006-008-integrated"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 85,
                 "template": {"metadata": {"labels": {"job": name}},
                              "spec": {"restartPolicy": "Never",
                                       "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                            "fsGroup": 65534,
                                                            "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "fixture", "image": image,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "/fixture/integrated_worker.py",
                                                                   *command],
                                                       "env": [{"name": "PYTHONDONTWRITEBYTECODE",
                                                                "value": "1"}],
                                                       "resources": {"requests": {"cpu": "5m",
                                                                                   "memory": "16Mi"},
                                                                     "limits": {"cpu": "100m",
                                                                                "memory": "64Mi"}},
                                                       "securityContext": {
                                                           "allowPrivilegeEscalation": False,
                                                           "readOnlyRootFilesystem": True,
                                                           "capabilities": {"drop": ["ALL"]}},
                                                       "volumeMounts": [
                                                           {"name": "code", "mountPath": "/fixture",
                                                            "readOnly": True},
                                                           {"name": "manifest", "mountPath": "/manifest",
                                                            "readOnly": True},
                                                           {"name": "state", "mountPath": "/state",
                                                            "readOnly": reader},
                                                       ]}],
                                       "volumes": [
                                           {"name": "code", "configMap": {"name": CODE,
                                                                              "defaultMode": 292}},
                                           {"name": "manifest", "configMap": {"name": MANIFEST,
                                                                                  "defaultMode": 292}},
                                           {"name": "state", "persistentVolumeClaim": {
                                               "claimName": CLAIM}},
                                       ]}}},
    }


def _run_job(lab, name, command, image, *, reader=False):
    lab.create(_job(name, command, image, reader=reader))
    lab.kubectl("-n", NS, "wait", "--for=condition=Complete", f"job/{name}",
                "--timeout=90s", timeout=100)
    job = json.loads(lab.kubectl("-n", NS, "get", "job", name, "-o", "json").stdout)
    pods = json.loads(lab.kubectl("-n", NS, "get", "pods", "-l", "job=" + name,
                                  "-o", "json").stdout)
    items = pods.get("items", [])
    if len(items) != 1:
        lab.block(f"Expected one synthetic observation Pod for {name}; found {len(items)}")
    pod_name = items[0]["metadata"]["name"]
    logs = lab.kubectl("-n", NS, "logs", pod_name)
    statuses = items[0].get("status", {}).get("containerStatuses", [])
    exit_code = statuses[0]["state"]["terminated"]["exitCode"] if statuses else None
    try:
        event = json.loads(logs.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        event = None
    return {"job_complete": any(c.get("type") == "Complete" and c.get("status") == "True"
                                 for c in job.get("status", {}).get("conditions", [])),
            "exit_code": exit_code, "event": event,
            "raw_job": job, "raw_pod": items[0],
            "raw_logs": logs.stdout + logs.stderr}


def run_integrated(lab, image):
    """Run the integrity-to-publication chain after the original evidence checks."""
    source_dataset = CASES / "SAF-K8S-0906-002" / "dataset_fixture.py"
    source_feature = CASES / "SAF-K8S-0907-005" / "feature_fixture.py"
    source_manifest = CASES / "SAF-K8S-0906-002" / "manifest.json"
    for required in (source_dataset, source_feature, source_manifest):
        if not required.is_file():
            lab.block(f"Required adjacent synthetic fixture is unavailable: {required.name}")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": CODE, "namespace": NS}, "immutable": True,
                "data": {"integrated_worker.py": (HERE / "integrated_worker.py").read_text(),
                         "dataset_fixture.py": source_dataset.read_text(),
                         "feature_fixture.py": source_feature.read_text()}})
    manifest_text = source_manifest.read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": MANIFEST, "namespace": NS}, "immutable": True,
                "data": {"manifest.json": manifest_text}})
    lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": CLAIM, "namespace": NS},
                "spec": {"accessModes": ["ReadWriteOnce"],
                         "resources": {"requests": {"storage": "64Mi"}}}})

    raw = {"producer": {}, "reader": {}}
    normalized_rejections = {}
    for scenario in SCENARIOS:
        producer = _run_job(lab, "saf1006-chain-p-" + scenario,
                            ["producer", scenario, "/state", "/manifest/manifest.json"], image)
        reader = _run_job(lab, "saf1006-chain-r-" + scenario,
                          ["reader", scenario, "/state", "/manifest/manifest.json"],
                          image, reader=True)
        raw["producer"][scenario] = producer
        raw["reader"][scenario] = reader
        event = producer["event"] or {}
        readback = reader["event"] or {}
        if scenario != "approved-clean":
            reason = {"wrong-bytes": "digest_or_size_mismatch",
                      "missing-partition": "inventory_or_dataset_id"}[scenario]
            normalized_rejections[scenario] = (
                producer["job_complete"] and producer["exit_code"] == 0
                and event == {"decision": "integrity_rejected", "reason": reason,
                              "scenario": scenario, "unchecked_reader_accepted": True,
                              "publish_input_created": False, "publish_outcome_created": False}
                and reader["job_complete"] and reader["exit_code"] == 0 and readback == {
                    "publish_input_present": False, "candidate_present": False,
                    "consumer_visible_publish_outcome": False, "scenario": scenario})

    clean = raw["producer"]["approved-clean"]
    clean_reader = raw["reader"]["approved-clean"]
    clean_ok = (clean["job_complete"] and clean["exit_code"] == 0
                and clean["event"] == {"decision": "published", "scenario": "approved-clean",
                                       "publish_input_created": True,
                                       "publish_outcome_created": True}
                and clean_reader["job_complete"] and clean_reader["exit_code"] == 0
                and clean_reader["event"] == {"candidate_present": True,
                                               "consumer_visible_publish_outcome": True,
                                               "exact_readback": True,
                                               "scenario": "approved-clean"})

    lab.check("green", "Before-use integrity rejects unchecked readable changes and missing partitions",
              all(normalized_rejections.values()) and len(normalized_rejections) == 2,
              {"wrong_bytes_no_publish": normalized_rejections.get("wrong-bytes", False),
               "missing_partition_no_publish": normalized_rejections.get("missing-partition", False)})
    lab.check("positive", "The independent reader sees the exact feature derived from verified partition bytes",
              clean_ok, {"approved_partition_and_manifest_bound_to_exact_readback": clean_ok})
    (lab.evidence / "1006-008-integrated-raw-observations.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
