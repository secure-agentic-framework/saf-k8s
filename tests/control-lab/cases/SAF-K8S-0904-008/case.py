"""Exercise a pre-consumption freshness and digest gate in disposable Kubernetes Jobs."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0904-008"
NAMESPACE = "saf-test"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
REFERENCE_INSTANT = "2025-06-01T12:00:00Z"
TRUSTED_SHA256 = "ce5a7af15a1cd190f49300c99992eb3973a2263214316ea9149ba6f8794782e0"
PROGRAMS = "saf0904008-programs"
INPUTS = ("valid", "stale", "mismatch")
SCOPE = (
    "One disposable Kind v1.36.1 cluster and five short Kubernetes Jobs using a previously used, "
    "digest-pinned Python image. Each Job has a read-only ConfigMap input, an init-container gate, "
    "and a downstream consumer that records only fixed synthetic dataset metadata. A fixed reference "
    "instant tests an inclusive 300-second freshness boundary, one-second staleness, and a canonical "
    "JSON SHA-256 mismatch. The case covers this fixture gate only; feature stores, provenance custody, "
    "poisoning/anomaly detection, and operational alerting remain unverified."
)


def _labels():
    return {"saf-k8s.example/control": CONTROL_ID, "saf-k8s.example/fixture": "synthetic"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_inputs():
    result = {}
    for name in INPUTS:
        root = HERE / "fixtures" / name
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        dataset = json.loads((root / "dataset.json").read_text(encoding="utf-8"))
        canonical = _canonical(dataset)
        if manifest.get("dataset_id") != "SYNTH-EVENTS-0904-008":
            raise ValueError(f"{name} fixture has an unexpected synthetic dataset ID")
        if manifest.get("sha256") != TRUSTED_SHA256:
            raise ValueError(f"{name} fixture manifest has an unexpected trusted digest")
        if name == "valid" and hashlib.sha256(canonical).hexdigest() != TRUSTED_SHA256:
            raise ValueError("trusted fixture digest does not match the canonical valid dataset")
        result[name] = {"manifest": manifest, "dataset": dataset,
                        "manifest_bytes": _canonical(manifest).decode("utf-8"),
                        "dataset_bytes": canonical.decode("utf-8")}
    if result["valid"]["dataset"] != result["stale"]["dataset"]:
        raise ValueError("stale fixture must contain the same fixed benign dataset")
    if result["valid"]["dataset"] == result["mismatch"]["dataset"]:
        raise ValueError("mismatch comparator must use its separate fixed benign dataset")
    return result


VALIDATOR = r'''import datetime, hashlib, json, os, pathlib, sys

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)

try:
    manifest = json.loads(pathlib.Path("/input/manifest.json").read_text(encoding="utf-8"))
    dataset = json.loads(pathlib.Path("/input/dataset.json").read_text(encoding="utf-8"))
    created = datetime.datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
    reference = datetime.datetime.fromisoformat(os.environ["REFERENCE_INSTANT"].replace("Z", "+00:00"))
    age = (reference - created).total_seconds()
    if manifest.get("dataset_id") != "SYNTH-EVENTS-0904-008" or dataset.get("dataset_id") != manifest.get("dataset_id"):
        raise ValueError("dataset-identity-mismatch")
    if age < 0 or age > int(os.environ["MAX_AGE_SECONDS"]):
        raise ValueError("stale")
    actual = hashlib.sha256(canonical(dataset)).hexdigest()
    if os.environ["POLICY_MODE"] == "full":
        if actual != manifest.get("sha256") or actual != os.environ["TRUSTED_SHA256"]:
            raise ValueError("sha256-mismatch")
    pathlib.Path("/receipt/validated.json").write_text(json.dumps({"dataset_id": manifest["dataset_id"],
        "created_at": manifest["created_at"], "age_seconds": age, "sha256": actual,
        "policy_mode": os.environ["POLICY_MODE"]}, sort_keys=True), encoding="utf-8")
    emit({"event": "validated", "dataset_id": manifest["dataset_id"], "age_seconds": age,
          "sha256": actual, "policy_mode": os.environ["POLICY_MODE"]})
except ValueError as error:
    reason = str(error) or "invalid-input"
    emit({"event": "rejected", "reason": reason})
    sys.exit(42)
except Exception as error:
    emit({"event": "fixture-error", "error_type": type(error).__name__})
    sys.exit(43)
'''

CONSUMER = r'''import hashlib, json, os, pathlib

dataset = json.loads(pathlib.Path("/input/dataset.json").read_text(encoding="utf-8"))
mode = os.environ["POLICY_MODE"]
receipt = None
if mode != "off":
    receipt_path = pathlib.Path("/receipt/validated.json")
    if not receipt_path.is_file():
        raise SystemExit("validation receipt missing")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt["dataset_id"] != dataset["dataset_id"]:
        raise SystemExit("validation receipt dataset mismatch")
canonical = json.dumps(dataset, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
print(json.dumps({"event": "consumed", "dataset_id": dataset["dataset_id"],
    "consumer": "SYNTH-DOWNSTREAM-0904-008", "policy_mode": mode,
    "sha256": hashlib.sha256(canonical).hexdigest(),
    "age_seconds": receipt.get("age_seconds") if receipt else None,
    "orders_30d": dataset["records"][0]["orders_30d"]}, sort_keys=True), flush=True)
'''


def _create_inputs(lab, fixtures):
    for name, value in fixtures.items():
        obj = lab.create({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": f"saf0904008-{name}", "namespace": NAMESPACE,
                         "labels": _labels()},
            "immutable": True,
            "data": {"manifest.json": value["manifest_bytes"],
                     "dataset.json": value["dataset_bytes"]},
        })
        if obj.get("immutable") is not True:
            raise ValueError(f"{name} input ConfigMap was not created immutable")


def _create_programs(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": PROGRAMS, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"validator.py": VALIDATOR, "consumer.py": CONSUMER},
    })


def _job_resource(name, input_name, policy_mode):
    env = [{"name": "REFERENCE_INSTANT", "value": REFERENCE_INSTANT},
           {"name": "TRUSTED_SHA256", "value": TRUSTED_SHA256},
           {"name": "MAX_AGE_SECONDS", "value": "300"},
           {"name": "POLICY_MODE", "value": policy_mode}]
    common_security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                       "capabilities": {"drop": ["ALL"]}}
    mounts = [{"name": "input", "mountPath": "/input", "readOnly": True},
              {"name": "programs", "mountPath": "/programs", "readOnly": True},
              {"name": "receipt", "mountPath": "/receipt"}]
    containers = [{"name": "consumer", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                   "command": ["python", "-B", "/programs/consumer.py"],
                   "env": env, "volumeMounts": [*mounts[:2], {**mounts[2], "readOnly": True}],
                   "securityContext": common_security, "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                 "limits": {"cpu": "100m", "memory": "64Mi"}}}]
    init = []
    if policy_mode != "off":
        init = [{"name": "validate", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-B", "/programs/validator.py"],
                 "env": env, "volumeMounts": mounts, "securityContext": common_security,
                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                               "limits": {"cpu": "100m", "memory": "64Mi"}}}]
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "template": {"metadata": {"labels": {**_labels(), "job": name}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "initContainers": init, "containers": containers,
                                       "volumes": [
                                           {"name": "input", "configMap": {"name": input_name}},
                                           {"name": "programs", "configMap": {"name": PROGRAMS}},
                                           {"name": "receipt", "emptyDir": {}}]}}}}


def _decode_log(lab, job, container):
    result = lab.kubectl("logs", f"job/{job}", "-c", container,
                         allow_failure=True, timeout=20)
    return result.stdout.strip()


def _job_result(lab, name, *, expected):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {item["type"] for item in job.get("status", {}).get("conditions", [])
                      if item.get("status") == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) > 1:
            lab.block(f"Job {name} has conflicting terminal conditions")
        if terminal:
            pods = json.loads(lab.kubectl("get", "pods", "-l", f"job={name}", "-o", "json").stdout)["items"]
            if len(pods) != 1:
                lab.block(f"Job {name} did not produce exactly one retained Pod")
            pod = pods[0]
            if not any(owner.get("controller") is True and owner.get("kind") == "Job"
                       and owner.get("uid") == job["metadata"]["uid"]
                       for owner in pod["metadata"].get("ownerReferences", [])):
                lab.block(f"Retained Pod is not owned by Job {name}")
            phase = pod.get("status", {}).get("phase")
            init_statuses = pod.get("status", {}).get("initContainerStatuses", [])
            app_statuses = pod.get("status", {}).get("containerStatuses", [])
            all_statuses = init_statuses + app_statuses
            infra_waits = {"ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError",
                           "CreateContainerError", "RunContainerError", "InvalidImageName"}
            for status in all_statuses:
                waiting = status.get("state", {}).get("waiting", {})
                if waiting.get("reason") in infra_waits:
                    lab.block(f"Job {name} is blocked by infrastructure: {waiting.get('reason')}")
            if phase in {"Pending", "Unknown"}:
                lab.kubectl("describe", f"pod/{pod['metadata']['name']}", allow_failure=True)
                lab.block(f"Job {name} reached a terminal condition without a scheduled Pod")
            result = {"condition": next(iter(terminal)), "job_status": job.get("status", {}),
                      "pod_phase": phase, "init_statuses": init_statuses,
                      "container_statuses": app_statuses,
                      "validator_log": _decode_log(lab, name, "validate") if expected != "off" else "",
                      "consumer_log": _decode_log(lab, name, "consumer")}
            return result
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job={name}", "-o", "json").stdout)["items"]
    for pod in pods:
        for status in pod.get("status", {}).get("initContainerStatuses", []) + pod.get("status", {}).get("containerStatuses", []):
            waiting = status.get("state", {}).get("waiting", {})
            if waiting.get("reason") in {"ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError"}:
                lab.block(f"Job {name} is blocked by infrastructure: {waiting.get('reason')}")
    lab.block(f"Job {name} did not reach a terminal Kubernetes condition")


def _json_line(value, where):
    try:
        return json.loads(value.splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        raise ValueError(f"{where} did not produce its stable JSON observation") from None


def _consume_ok(result, *, mode, age=None, digest=TRUSTED_SHA256):
    if result["condition"] != "Complete" or result["pod_phase"] != "Succeeded":
        return False
    if result["job_status"].get("succeeded") != 1 or result["job_status"].get("failed", 0) != 0:
        return False
    app = next((item for item in result["container_statuses"] if item.get("name") == "consumer"), {})
    if app.get("state", {}).get("terminated", {}).get("exitCode") != 0:
        return False
    observed = _json_line(result["consumer_log"], "downstream consumer")
    if not (observed.get("event") == "consumed" and observed.get("dataset_id") == "SYNTH-EVENTS-0904-008"
            and observed.get("consumer") == "SYNTH-DOWNSTREAM-0904-008"
            and observed.get("policy_mode") == mode and observed.get("sha256") == digest):
        return False
    if age is not None and observed.get("age_seconds") != age:
        return False
    return observed


def _reject_ok(result, reason):
    if result["condition"] != "Failed" or result["pod_phase"] != "Failed":
        return False, result
    if result["job_status"].get("failed") != 1 or result["job_status"].get("succeeded", 0) != 0:
        return False, result
    init = next((item for item in result["init_statuses"] if item.get("name") == "validate"), {})
    if init.get("state", {}).get("terminated", {}).get("exitCode") != 42:
        return False, result
    rejected = _json_line(result["validator_log"], "validator")
    consumer = next((item for item in result["container_statuses"] if item.get("name") == "consumer"), {})
    never_started = (not consumer.get("containerID") and consumer.get("restartCount", 0) == 0
                     and "terminated" not in consumer.get("state", {}))
    blocked = never_started and result["consumer_log"] == ""
    return (rejected == {"event": "rejected", "reason": reason} and blocked,
            {"job_condition": result["condition"], "pod_phase": result["pod_phase"],
             "init_exit": 42, "gate_receipt": rejected, "consumer_never_started": blocked})


def run(lab):
    fixtures = _load_inputs()
    _create_inputs(lab, fixtures)
    _create_programs(lab)

    # Red: with the gate absent, the ordinary fixed stale sample reaches the consumer.
    lab.create(_job_resource("saf0904008-red-off", "saf0904008-stale", "off"))
    red = _job_result(lab, "saf0904008-red-off", expected="off")
    red_observed = _consume_ok(red, mode="off")
    lab.check("red", "With the validation gate off, the downstream consumer reads the fixed stale sample",
              bool(red_observed), red_observed or red)

    # Green: the full gate rejects distinct one-second-stale and digest-mismatch inputs before consume.
    lab.create(_job_resource("saf0904008-green-stale", "saf0904008-stale", "full"))
    stale = _job_result(lab, "saf0904008-green-stale", expected="full")
    stale_ok, stale_observation = _reject_ok(stale, "stale")
    lab.check("green", "The full gate fails the stale Job before its consumer container starts",
              stale_ok, stale_observation)

    lab.create(_job_resource("saf0904008-green-hash", "saf0904008-mismatch", "full"))
    mismatch = _job_result(lab, "saf0904008-green-hash", expected="full")
    mismatch_ok, mismatch_observation = _reject_ok(mismatch, "sha256-mismatch")
    lab.check("green", "The full gate fails the digest-mismatch Job before its consumer container starts",
              mismatch_ok, mismatch_observation)

    # Positive boundary: age exactly 300 seconds is inclusive and the valid digest is consumed.
    lab.create(_job_resource("saf0904008-positive-boundary", "saf0904008-valid", "full"))
    boundary = _job_result(lab, "saf0904008-positive-boundary", expected="full")
    boundary_ok = _consume_ok(boundary, mode="full", age=300)
    lab.check("positive", "The full gate accepts the exact freshness boundary and consumes canonical trusted bytes",
              bool(boundary_ok), boundary_ok or boundary)

    # Weak comparator: freshness-only mode accepts a fixed ordinary content difference at the same boundary.
    lab.create(_job_resource("saf0904008-positive-weak", "saf0904008-mismatch", "freshness-only"))
    weak = _job_result(lab, "saf0904008-positive-weak", expected="freshness-only")
    weak_observed = _consume_ok(weak, mode="freshness-only", age=300,
                                digest=hashlib.sha256(_canonical(fixtures["mismatch"]["dataset"])).hexdigest())
    lab.check("red", "Freshness-only comparator consumes the fixed content-mismatch sample, showing integrity is separate",
              bool(weak_observed) and weak_observed["sha256"] != TRUSTED_SHA256,
              weak_observed or weak)

    (lab.evidence / "feature-gate.raw.json").write_text(json.dumps(
        {"without_gate": red, "stale": stale, "digest_mismatch": mismatch,
         "inclusive_boundary": boundary, "without_integrity": weak}, indent=2) + "\n")
