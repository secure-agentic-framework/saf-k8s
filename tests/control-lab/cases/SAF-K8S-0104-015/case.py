"""Retain and compare two synthetic Kubernetes posture receipts on a case-owned PVC."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
CONTROL_LABEL = "saf-k8s-control"
CONTROL_ID = "SAF-K8S-0104-015"
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
SCOPE = (
    "Disposable kind v1.36.1 single-node demonstration. The two dated assessment "
    "receipts are synthetic JSON fixtures with stable illustrative check IDs; no CIS "
    "scanner or production cluster is assessed. A case-owned hostPath PV/PVC retains "
    "the fixture bytes across collector and reader Job/Pod turnover only for this lab "
    "run. Readers have read-only archive mounts, and trends reject incompatible reports. "
    "Retain does not protect against cluster deletion, node loss, privileged "
    "deletion, or provide production immutability, backup, access control, or retention "
    "policy."
)


def _read_receipt(name):
    raw = (HERE / "receipts" / name).read_bytes()
    parsed = json.loads(raw)
    if parsed.get("synthetic") is not True:
        raise ValueError(f"{name} is not explicitly marked synthetic")
    if not parsed.get("report_id") or not parsed.get("assessment_date"):
        raise ValueError(f"{name} lacks report identity or assessment date")
    if not parsed.get("profile") or not parsed.get("resource_scope"):
        raise ValueError(f"{name} lacks profile or resource scope")
    return raw, parsed


def _trend(before, after):
    fields = ("benchmark", "benchmark_version", "profile", "resource_scope")
    if any(before[key] != after[key] for key in fields):
        raise ValueError("benchmark profile or resource scope differs")
    if before["assessment_date"] >= after["assessment_date"]:
        raise ValueError("assessment dates are out of order")
    old = {row["check_id"]: row["status"] for row in before["checks"]}
    new = {row["check_id"]: row["status"] for row in after["checks"]}
    if len(old) != len(before["checks"]) or len(new) != len(after["checks"]):
        raise ValueError("report has duplicate check IDs")
    if old.keys() != new.keys():
        raise ValueError("assessed check population differs")
    regressions = sorted(key for key in old if old[key] == "PASS" and new[key] == "FAIL")
    sustained = sorted(key for key in old if old[key] == new[key] == "PASS")
    return regressions, sustained


def _metadata(name, value):
    return {"name": name, "namespace": NAMESPACE,
            "labels": {CONTROL_LABEL: CONTROL_ID, "app.kubernetes.io/part-of": "saf-case"},
            **value}


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def _get_json(lab, resource):
    return json.loads(lab.kubectl("get", resource, "-o", "json").stdout)


def _job(name, command, *, volumes, mounts):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": _metadata(name, {}),
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "template": {"metadata": {"labels": {CONTROL_LABEL: CONTROL_ID}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "containers": [{"name": "case-task", "image": BUSYBOX_IMAGE,
                                                       "command": ["/bin/sh", "-ec", command],
                                                       "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                       "securityContext": {"runAsUser": 0,
                                                                           "allowPrivilegeEscalation": False,
                                                                           "capabilities": {"drop": ["ALL"]},
                                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                                       "volumeMounts": mounts}],
                                       "volumes": volumes}}}}


def _wait_job(lab, name):
    lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=100s", timeout=110)


def _delete_job(lab, name):
    lab.kubectl("delete", "job", name, "--ignore-not-found=true", "--wait=true", timeout=45)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={name}",
                                  "-o", "json").stdout)
    return len(pods.get("items", [])) == 0


def _reader(lab, name):
    job = _job(name, "cd /evidence; "
               "if touch reader-output 2>/tmp/archive-write-error; then exit 45; fi; "
               "grep -qi 'read-only file system' /tmp/archive-write-error; "
               "echo READ_ONLY_MOUNT_CONFIRMED; sha256sum baseline.json followup.json; sha256sum -c manifest.sha256; printf '\nREPORTS\n'; cat baseline.json; printf '\nFOLLOWUP\n'; cat followup.json",
               volumes=[{"name": "archive", "persistentVolumeClaim": {"claimName": "saf-evidence"}}],
               mounts=[{"name": "archive", "mountPath": "/evidence", "readOnly": True}])
    _apply(lab, job)
    _wait_job(lab, name)
    output = lab.kubectl("logs", f"job/{name}").stdout
    hashes = {}
    for line in output.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (baseline\.json|followup\.json)", line.strip())
        if match:
            hashes[match.group(2)] = match.group(1)
    retained = output.split("REPORTS\n", 1)[1].split("FOLLOWUP\n", 1)
    return output, hashes, tuple(json.loads(text) for text in retained)


def run(lab):
    before_raw, before = _read_receipt("baseline.json")
    after_raw, after = _read_receipt("followup.json")
    expected = {"baseline.json": hashlib.sha256(before_raw).hexdigest(),
                "followup.json": hashlib.sha256(after_raw).hexdigest()}
    assert before["report_id"] != after["report_id"]
    assert before["assessment_date"] < after["assessment_date"]

    suffix = lab.cluster.removeprefix("saf-lab-")
    pv_name = f"saf-evidence-{suffix}"
    node_name = f"{lab.cluster}-control-plane"
    archive_path = f"/var/local/{lab.cluster}-evidence"
    resources = []
    try:
        # Counterfactual: a mutable latest-only object overwrites its sole record.
        latest = {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": _metadata("saf-latest-only", {}),
                  "data": {"latest.json": before_raw.decode()}}
        _apply(lab, latest)
        resources.append(("configmap", "saf-latest-only"))
        prior_visible = json.loads(_get_json(lab, "configmap/saf-latest-only")["data"]["latest.json"])
        latest["data"]["latest.json"] = after_raw.decode()
        _apply(lab, latest)
        only_current = json.loads(_get_json(lab, "configmap/saf-latest-only")["data"]["latest.json"])
        lab.check("red", "A mutable latest-only receipt cannot establish the prior assessment",
                  prior_visible["report_id"] == before["report_id"] and
                  only_current["report_id"] == after["report_id"] and
                  before["report_id"] not in _get_json(lab, "configmap/saf-latest-only")["data"]["latest.json"],
                  {"initial_report_id": prior_visible["report_id"],
                   "latest_report_id": only_current["report_id"],
                   "prior_report_present_after_overwrite": False})

        # The PVC uses an explicit single-node hostPath PV and Retain reclaim policy.
        pv = {"apiVersion": "v1", "kind": "PersistentVolume",
              "metadata": {"name": pv_name, "labels": {CONTROL_LABEL: CONTROL_ID}},
              "spec": {"capacity": {"storage": "1Mi"}, "accessModes": ["ReadWriteOnce"],
                       "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "",
                       "hostPath": {"path": archive_path, "type": "DirectoryOrCreate"},
                       "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                           {"key": "kubernetes.io/hostname", "operator": "In", "values": [node_name]}]}]}}}}
        _apply(lab, pv)
        resources.append(("pv", pv_name))
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
               "metadata": _metadata("saf-evidence", {}),
               "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "",
                        "volumeName": pv_name, "resources": {"requests": {"storage": "1Mi"}}}}
        _apply(lab, pvc)
        resources.append(("pvc", "saf-evidence"))
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/saf-evidence", "--timeout=45s")

        inputs = {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": _metadata("saf-receipt-input", {}), "immutable": True,
                  "data": {"baseline.json": before_raw.decode(), "followup.json": after_raw.decode()}}
        _apply(lab, inputs)
        resources.append(("configmap", "saf-receipt-input"))
        collector = _job("saf-receipt-collector",
                         "mkdir -p /evidence && cp /input/baseline.json /evidence/baseline.json && "
                         "cp /input/followup.json /evidence/followup.json && cd /evidence && "
                         "sha256sum baseline.json followup.json > manifest.sha256 && sync",
                         volumes=[{"name": "input", "configMap": {"name": "saf-receipt-input"}},
                                  {"name": "archive", "persistentVolumeClaim": {"claimName": "saf-evidence"}}],
                         mounts=[{"name": "input", "mountPath": "/input", "readOnly": True},
                                 {"name": "archive", "mountPath": "/evidence"}])
        _apply(lab, collector)
        resources.append(("job", "saf-receipt-collector"))
        _wait_job(lab, "saf-receipt-collector")
        collector_turned_over = _delete_job(lab, "saf-receipt-collector")

        reader1_output, receipt1, reports1 = _reader(lab, "saf-independent-reader-a")
        reader1_turned_over = _delete_job(lab, "saf-independent-reader-a")
        reader2_output, receipt2, reports2 = _reader(lab, "saf-independent-reader-b")
        reader2_turned_over = _delete_job(lab, "saf-independent-reader-b")

        exact_stored_receipts = receipt1 == expected
        repeated_receipts_match = receipt1 == receipt2 and set(receipt2) == set(expected)
        manifest_verified_twice = all("baseline.json: OK" in out and "followup.json: OK" in out
                                      for out in (reader1_output, reader2_output))
        lab.check("green", "Two independent readers recover both retained report digests after Job turnover",
                  collector_turned_over and reader1_turned_over and reader2_turned_over and
                  exact_stored_receipts and repeated_receipts_match and manifest_verified_twice and reports1 == reports2,
                  {"collector_pods_gone": collector_turned_over,
                   "reader_a_pods_gone": reader1_turned_over,
                   "reader_b_pods_gone": reader2_turned_over,
                   "expected_equals_reader_a": exact_stored_receipts,
                   "reader_a_equals_reader_b": repeated_receipts_match,
                   "receipt_sha256": receipt2})

        read_only = all("READ_ONLY_MOUNT_CONFIRMED" in output for output in (reader1_output, reader2_output))
        lab.check("green", "Both live archive readers can retrieve reports and their mounts reject writes",
                  read_only, {"reader_mounts_reject_writes": read_only})

        baseline, followup = reports2
        different_scope = {**followup, "resource_scope": "other-owned-fixture"}
        duplicate_check = deepcopy(followup)
        duplicate_check["checks"].append(duplicate_check["checks"][0])
        missing_check = {**followup, "checks": followup["checks"][:-1]}
        reasons = {}
        for label, altered in (("changed_scope", different_scope), ("duplicate_check", duplicate_check),
                               ("missing_check", missing_check)):
            try:
                _trend(baseline, altered)
            except ValueError as error:
                reasons[label] = str(error)
        lab.check("red", "An incompatible scope or population cannot produce a misleading trend",
                  reasons == {"changed_scope": "benchmark profile or resource scope differs",
                              "duplicate_check": "report has duplicate check IDs",
                              "missing_check": "assessed check population differs"}, reasons)

        regressions, sustained = _trend(*reports2)
        lab.check("positive", "Stable check IDs show a regression and a sustained passing posture",
                  regressions == ["1.2.1"] and sustained == ["1.2.2"],
                  {"comparison_key": ["benchmark", "benchmark_version", "profile", "resource_scope", "check_id"],
                   "regressed_check_ids": regressions,
                   "sustained_pass_check_ids": sustained,
                   "report_dates": [before["assessment_date"], after["assessment_date"]],
                   "scope": before["resource_scope"]})
    finally:
        # Delete all names created by this case; the lab runner also deletes its fresh cluster.
        for job_name in ("saf-independent-reader-b", "saf-independent-reader-a", "saf-receipt-collector"):
            lab.kubectl("delete", "job", job_name, "--ignore-not-found=true", "--wait=true", timeout=60)
        for kind, name in reversed(resources):
            lab.kubectl("delete", kind, name, "--ignore-not-found=true", "--wait=true", timeout=60)
        if ("pvc", "saf-evidence") in resources:
            lab.kubectl("delete", "pvc", "saf-evidence", "--ignore-not-found=true", "--wait=true", timeout=60)
        if ("pv", pv_name) in resources:
            lab.kubectl("delete", "pv", pv_name, "--ignore-not-found=true", "--wait=true", timeout=60)
