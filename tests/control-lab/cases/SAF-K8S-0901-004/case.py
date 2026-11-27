"""Check bounded, digest-verified recovery of two inert synthetic snapshots."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "snapshots.json"
WORKLOAD_PATH = HERE / "fixtures" / "workload.py"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
CONTROL_ID = "SAF-K8S-0901-004"
LABEL_CONTROL = "saf-k8s.example/control"
LABEL_FIXTURE = "saf-k8s.example/fixture"
SNAPSHOT_NAMES = {"a": "saf0901004-a", "b": "saf0901004-b"}
TARGET_NAME = "saf0901004-recovery-state"
WORKLOAD_NAME = "saf0901004-recovery-check"
MAX_RESTORE_ATTEMPTS = 2
JOB_TIMEOUT = 120
SCOPE = (
    "One disposable Kind v1.36.1 cluster and the saf-test namespace; two immutable, "
    "case-owned ConfigMaps carrying synthetic named snapshots; a deliberately changed "
    "target ConfigMap; one local bounded restore function; and two short digest-pinned "
    "Python Jobs. The case checks fixture SHA-256 values, altered-byte rejection, an "
    "over-limit retry request, exact approved payload/label/annotation restoration, and "
    "Job conditions and Pod counts. It additionally copies one fixed synthetic checkpoint "
    "across source and backup PVCs and restores/read-checks it on a third fresh PVC using "
    "three short tokenless Jobs. The three claims use the selected storage class in this "
    "same cluster and do not establish independent failure domains. It does not exercise "
    "an ML framework, training operator, real checkpoint store, distributed training, "
    "data re-ingestion, external backup service, or production retry/rollback configuration."
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _load_fixture():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if fixture.get("fixture_only") is not True:
        raise ValueError("fixture must be explicitly marked fixture_only")
    snapshots = fixture.get("snapshots", [])
    if {item.get("snapshot_id") for item in snapshots} != {
        "SYNTH-SNAPSHOT-0901-004-A", "SYNTH-SNAPSHOT-0901-004-B"
    }:
        raise ValueError("fixture snapshot identifiers do not match the exact allowlist")
    if {item.get("configmap_name") for item in snapshots} != set(SNAPSHOT_NAMES.values()):
        raise ValueError("fixture ConfigMap names do not match the exact allowlist")
    for item in snapshots:
        snapshot_bytes = _canonical({"snapshot_id": item["snapshot_id"], "object": item["object"]})
        if hashlib.sha256(snapshot_bytes).hexdigest() != item.get("trusted_sha256"):
            raise ValueError(f"checked-in digest mismatch for {item.get('snapshot_id')}")
        if item["object"].get("kind") != "ConfigMap":
            raise ValueError("only synthetic ConfigMap state is allowed")
        metadata = item["object"].get("metadata", {})
        if metadata.get("name") != TARGET_NAME or metadata.get("namespace") != NAMESPACE:
            raise ValueError("fixture target identity is outside the exact allowlist")
        if metadata.get("labels", {}).get(LABEL_CONTROL) != CONTROL_ID:
            raise ValueError("fixture ownership label is missing")
    return fixture


def _labels():
    return {LABEL_CONTROL: CONTROL_ID, LABEL_FIXTURE: "true"}


def _api_get(lab, name):
    result = lab.kubectl("get", "configmap", name, "-o", "json", "--ignore-not-found")
    return json.loads(result.stdout) if result.stdout.strip() else None


def _create_snapshot(lab, item):
    name = item["configmap_name"]
    if name not in SNAPSHOT_NAMES.values() or _api_get(lab, name) is not None:
        lab.block("Refusing to overwrite an object outside the exact snapshot allowlist")
    payload = _canonical({"snapshot_id": item["snapshot_id"], "object": item["object"]})
    digest = item["trusted_sha256"]
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"snapshot.json": payload.decode(), "trusted.sha256": digest},
    })


def _snapshot_bytes(lab, item):
    obj = _api_get(lab, item["configmap_name"])
    if obj is None:
        lab.block("An allowlisted snapshot is missing from the Kubernetes API")
    metadata = obj.get("metadata", {})
    data = obj.get("data", {})
    if (metadata.get("namespace") != NAMESPACE
            or metadata.get("labels", {}) != _labels()
            or obj.get("immutable") is not True):
        lab.block("Snapshot API object lacks exact case ownership or immutability")
    raw = data.get("snapshot.json", "").encode()
    if (hashlib.sha256(raw).hexdigest() != item["trusted_sha256"]
            or data.get("trusted.sha256") != item["trusted_sha256"]):
        lab.block("Snapshot bytes or API-carried digest do not match the trusted fixture digest")
    parsed = json.loads(raw)
    if parsed != {"snapshot_id": item["snapshot_id"], "object": item["object"]}:
        lab.block("Snapshot API payload differs from the exact checked-in fixture")
    return raw


def _start_job(lab, name, snapshot_configmap, expected_digest):
    if snapshot_configmap not in set(SNAPSHOT_NAMES.values()) | {"saf0901004-tampered"}:
        lab.block("Refusing to mount a snapshot outside the exact fixture allowlist")
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {"metadata": {"labels": _labels()}, "spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "verify", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "/workload/workload.py", "verify",
                                "/snapshot/snapshot.json", "/snapshot/trusted.sha256",
                                expected_digest],
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [
                        {"name": "snapshot", "mountPath": "/snapshot", "readOnly": True},
                        {"name": "workload", "mountPath": "/workload", "readOnly": True},
                    ],
                }],
                "volumes": [
                    {"name": "snapshot", "configMap": {"name": snapshot_configmap}},
                    {"name": "workload", "configMap": {"name": WORKLOAD_NAME}},
                ],
            }},
        },
    }
    lab.create(job)


def _job_result(lab, name):
    deadline = time.monotonic() + JOB_TIMEOUT
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {c["type"] for c in job.get("status", {}).get("conditions", [])
                      if c.get("status") == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) == 1:
            pods = json.loads(lab.kubectl(
                "get", "pods", "-l", f"batch.kubernetes.io/job-name={name}", "-o", "json"
            ).stdout)["items"]
            logs = lab.kubectl("logs", f"job/{name}", allow_failure=True).stdout.strip()
            return terminal.pop(), job, pods, logs
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    lab.block(f"Job {name} did not reach a terminal condition")


def _restore(lab, item, *, candidate_bytes=None, attempts=1):
    """Use one bounded path for digest checks and API restoration."""
    if type(attempts) is not int or attempts < 1 or attempts > MAX_RESTORE_ATTEMPTS:
        return {"restored": False, "reason": "retry-limit-exceeded", "attempts": attempts}
    trusted = _snapshot_bytes(lab, item)
    candidate = trusted if candidate_bytes is None else candidate_bytes
    actual = hashlib.sha256(candidate).hexdigest()
    if actual != item["trusted_sha256"]:
        return {"restored": False, "reason": "digest-mismatch", "attempts": attempts,
                "observed_sha256": actual, "expected_sha256": item["trusted_sha256"]}
    snapshot = json.loads(candidate)
    resource = snapshot["object"]
    if resource["metadata"]["name"] != TARGET_NAME or resource["metadata"]["namespace"] != NAMESPACE:
        return {"restored": False, "reason": "target-identity-mismatch", "attempts": attempts}
    target = _api_get(lab, TARGET_NAME)
    metadata = (target or {}).get("metadata", {})
    if (metadata.get("labels", {}).get(LABEL_CONTROL) != CONTROL_ID
            or not metadata.get("resourceVersion") or not metadata.get("uid")):
        lab.block("The restore target is missing or is outside the owned fixture")
    resource["metadata"].update(resourceVersion=metadata["resourceVersion"], uid=metadata["uid"])
    result = lab.kubectl("replace", "-f", "-", "-o", "json", payload=json.dumps(resource))
    observed = json.loads(result.stdout)
    expected_meta = resource["metadata"]
    observed_meta = observed.get("metadata", {})
    exact = (
        observed.get("data", {}) == resource.get("data", {})
        and observed_meta.get("labels", {}) == expected_meta.get("labels", {})
        and observed_meta.get("annotations", {}) == expected_meta.get("annotations", {})
        and observed_meta.get("uid") == metadata["uid"]
    )
    return {"restored": exact, "reason": "restored" if exact else "api-state-mismatch",
            "attempts": attempts, "snapshot_id": snapshot["snapshot_id"],
            "sha256": actual, "data": observed.get("data", {}),
            "labels": observed_meta.get("labels", {}),
            "annotations": observed_meta.get("annotations", {})}


def _target(lab):
    obj = _api_get(lab, TARGET_NAME)
    if obj is None:
        return None
    meta = obj.get("metadata", {})
    return {"name": meta.get("name"), "namespace": meta.get("namespace"),
            "data": obj.get("data", {}), "labels": meta.get("labels", {}),
            "annotations": meta.get("annotations", {})}


def run(lab):
    fixture = _load_fixture()
    snapshots = {item["snapshot_id"][-1]: item for item in fixture["snapshots"]}
    item = snapshots["B"]
    evidence = {
        "control_id": CONTROL_ID, "fixture_only": True,
        "image_refs": {"kind_node": NODE_IMAGE, "job": PYTHON_IMAGE},
        "max_restore_attempts": MAX_RESTORE_ATTEMPTS,
        "snapshot_records": [], "checks": [],
    }

    for entry in fixture["snapshots"]:
        _create_snapshot(lab, entry)
        raw = _snapshot_bytes(lab, entry)
        evidence["snapshot_records"].append({
            "snapshot_id": entry["snapshot_id"], "configmap": entry["configmap_name"],
            "trusted_sha256": entry["trusted_sha256"],
            "api_sha256": hashlib.sha256(raw).hexdigest(),
            "immutable": True,
        })
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": WORKLOAD_NAME, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True, "data": {"workload.py": WORKLOAD_PATH.read_text(encoding="utf-8")},
    })

    initial = dict(item["object"])
    initial["data"] = {"checkpoint.json": "synthetic-unapproved-state",
                       "metadata.json": "synthetic-unapproved-metadata"}
    initial["metadata"] = dict(initial["metadata"])
    initial["metadata"]["labels"] = dict(initial["metadata"]["labels"])
    initial["metadata"]["labels"]["saf-k8s.example/state"] = "modified-fixture"
    lab.create(initial)
    changed = _target(lab)
    altered = _canonical({"snapshot_id": item["snapshot_id"], "object": item["object"]}) + b" "
    tamper = _restore(lab, item, candidate_bytes=altered)
    lab.check("red", "The bounded restore path rejects altered snapshot bytes before changing the target",
              not tamper["restored"] and tamper["reason"] == "digest-mismatch"
              and _target(lab) == changed,
              {"restore": tamper, "target_unchanged": _target(lab) == changed})
    evidence["checks"].append({"phase": "red", "restore": tamper, "target": changed})

    over_limit = _restore(lab, item, attempts=MAX_RESTORE_ATTEMPTS + 1)
    lab.check("red", "The same restore path refuses attempts beyond its explicit bound",
              not over_limit["restored"] and over_limit["reason"] == "retry-limit-exceeded"
              and _target(lab) == changed,
              {"restore": over_limit, "target_unchanged": _target(lab) == changed})
    evidence["checks"].append({"phase": "red", "restore": over_limit})

    # Failed checksum Job: its configured backoffLimit is zero, so one failed Pod is expected.
    tampered_snapshot = _canonical({"snapshot_id": item["snapshot_id"], "object": item["object"]}) + b"\n"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf0901004-tampered", "namespace": NAMESPACE,
                             "labels": _labels()},
                "immutable": True,
                "data": {"snapshot.json": tampered_snapshot.decode(),
                         "trusted.sha256": item["trusted_sha256"]}})
    _start_job(lab, "saf0901004-red", "saf0901004-tampered", item["trusted_sha256"])
    failed_state, failed_job, failed_pods, failed_logs = _job_result(lab, "saf0901004-red")
    fail_ok = (failed_state == "Failed" and failed_job["spec"].get("backoffLimit") == 0
               and failed_job.get("status", {}).get("failed", 0) == 1 and len(failed_pods) == 1
               and json.loads(failed_logs).get("result") == "digest-mismatch"
               and json.loads(failed_logs).get("actual_sha256") != item["trusted_sha256"]
               and json.loads(failed_logs).get("recorded_sha256_matches") is True)
    lab.check("positive", "The failed integrity Job records digest rejection and bounded Job status",
              fail_ok,
              {"job_condition": failed_state, "backoffLimit": failed_job["spec"].get("backoffLimit"),
               "failed_pods": failed_job.get("status", {}).get("failed", 0),
               "pod_count": len(failed_pods), "logs": failed_logs})
    evidence["checks"].append({"phase": "positive", "job": failed_job,
                               "pod_count": len(failed_pods), "logs": failed_logs})

    _start_job(lab, "saf0901004-green", item["configmap_name"], item["trusted_sha256"])
    green_state, green_job, green_pods, green_logs = _job_result(lab, "saf0901004-green")
    positive_ok = (green_state == "Complete" and green_job["spec"].get("backoffLimit") == 0
                   and green_job.get("status", {}).get("succeeded", 0) == 1
                   and len(green_pods) == 1 and json.loads(green_logs).get("result") == "verified"
                   and json.loads(green_logs).get("actual_sha256") == item["trusted_sha256"])
    lab.check("positive", "A pinned benign Kubernetes Job independently verifies the approved snapshot",
              positive_ok,
              {"job_condition": green_state, "backoffLimit": green_job["spec"].get("backoffLimit"),
               "succeeded_pods": green_job.get("status", {}).get("succeeded", 0),
               "pod_count": len(green_pods), "logs": green_logs})
    evidence["checks"].append({"phase": "positive", "job": green_job,
                               "pod_count": len(green_pods), "logs": green_logs})

    restored = _restore(lab, item, attempts=1)
    observed = _target(lab)
    expected = {"name": TARGET_NAME, "namespace": NAMESPACE,
                "data": item["object"]["data"],
                "labels": item["object"]["metadata"]["labels"],
                "annotations": item["object"]["metadata"]["annotations"]}
    green_ok = restored["restored"] and observed == expected and restored["snapshot_id"] == item["snapshot_id"]
    lab.check("green", "Recovery restores the exact previously approved bytes and metadata through the API",
              green_ok,
              {"restore": restored, "api_observed": observed, "expected": expected})
    evidence["checks"].append({"phase": "green", "restore": restored,
                               "api_observed": observed, "expected": expected})

    supplement_path = HERE / "pvc_backup.py"
    supplement_spec = importlib.util.spec_from_file_location("saf_0901_004_pvc_backup", supplement_path)
    if supplement_spec is None or supplement_spec.loader is None:
        lab.block("PVC checkpoint supplement is unavailable")
    supplement = importlib.util.module_from_spec(supplement_spec)
    supplement_spec.loader.exec_module(supplement)
    evidence["pvc_backup_restore"] = supplement.run(lab, item)
    retry_path = HERE / "job_retry.py"
    retry_spec = importlib.util.spec_from_file_location("saf_0901_004_job_retry", retry_path)
    if retry_spec is None or retry_spec.loader is None:
        lab.block("Job retry continuation supplement is unavailable")
    retry = importlib.util.module_from_spec(retry_spec)
    retry_spec.loader.exec_module(retry)
    evidence["job_retry_continuation"] = retry.run(lab, item, supplement)
    (lab.evidence / "recovery-integrity.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
