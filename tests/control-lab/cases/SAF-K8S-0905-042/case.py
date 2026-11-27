"""Generate bounded CycloneDX-style ML lineage metadata from one tiny K8s Job."""
from datetime import datetime, timezone
import hashlib
import json
import platform
import re
import time
import uuid
from pathlib import Path

CONTROL_ID = "SAF-K8S-0905-042"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PYTHON_IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
NS = "saf-test"
HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
JOB = "saf-mlbom-train"
CONFIG = "saf-mlbom-input"
SCOPE = (
    "One disposable Kind v1.36.1 cluster and namespace saf-test; one tokenless, restricted, "
    "single-completion Python Job trains a deterministic linear model from three fixed local "
    "synthetic records. The case captures dataset/config/model hashes, hyperparameters, "
    "trainer/runtime versions, and the actual Job/Pod/Node identity and selected Node runtime "
    "fields, then emits a schema-validated CycloneDX 1.7 ML-BOM. This fixture has no third-party ML framework; "
    "CTA-2114 clause-level alignment remains pending authorized source review. It does not demonstrate production "
    "workflow coverage or durable storage/attachment, which the catalog scope excludes."
)

TRAINER = r'''import hashlib, json, os, platform
from pathlib import Path
base = Path("/fixture")
dataset_raw = (base / "dataset.json").read_bytes()
config_raw = (base / "training-config.json").read_bytes()
dataset = json.loads(dataset_raw)
config = json.loads(config_raw)
points = dataset["records"]
xs = [float(row["x"]) for row in points]
ys = [float(row["y"]) for row in points]
mean_x = sum(xs) / len(xs)
mean_y = sum(ys) / len(ys)
denominator = sum((x - mean_x) ** 2 for x in xs)
weight = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator
bias = mean_y - weight * mean_x
model = {"algorithm": config["algorithm"], "bias": bias, "weight": weight}
model_raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
receipt = {
    "dataset_id": dataset["dataset_id"],
    "dataset_sha256": hashlib.sha256(dataset_raw).hexdigest(),
    "training_config_sha256": hashlib.sha256(config_raw).hexdigest(),
    "model_sha256": hashlib.sha256(model_raw).hexdigest(),
    "model": model,
    "hyperparameters": config,
    "trainer_name": "saf-toy-linear-trainer",
    "trainer_version": "1.0.0",
    "python_version": platform.python_version(),
    "third_party_dependencies": [],
    "node_name": os.environ["NODE_NAME"],
}
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
'''


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical_hash(value):
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _validate_metadata(bom, expected):
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.7":
        return False, "format_marker_missing_or_unexpected"
    components = bom.get("components", [])
    if len(components) != 1:
        return False, "single_dataset_component_required"
    model = bom.get("metadata", {}).get("component")
    data = next((c for c in components if c.get("type") == "data"), None)
    if not model or not data:
        return False, "model_or_dataset_component_missing"
    props = {item.get("name"): item.get("value") for item in model.get("properties", [])}
    required = {
        "saf:dataset:sha256": expected["dataset_sha256"],
        "saf:training-config:sha256": expected["training_config_sha256"],
        "saf:model:sha256": expected["model_sha256"],
        "saf:trainer:name": "saf-toy-linear-trainer",
        "saf:trainer:version": "1.0.0",
        "saf:python:version": expected["python_version"],
        "saf:hyperparameters:json": json.dumps(expected["hyperparameters"], sort_keys=True, separators=(",", ":")),
        "saf:infrastructure:job-uid": expected["job_uid"],
        "saf:infrastructure:pod-uid": expected["pod_uid"],
        "saf:infrastructure:node-uid": expected["node_uid"],
        "saf:infrastructure:node-name": expected["node_name"],
        "saf:infrastructure:kubelet-version": expected["kubelet_version"],
        "saf:infrastructure:container-runtime": expected["container_runtime_version"],
        "saf:training:image": PYTHON_IMAGE,
    }
    if any(props.get(key) != value for key, value in required.items()):
        return False, "lineage_metadata_missing_or_mismatched"
    if data.get("bom-ref") != "dataset-saf-mlbom-toy-v1":
        return False, "dataset_reference_missing"
    if model.get("modelCard", {}).get("modelParameters", {}).get("datasets") != [{"ref": data["bom-ref"]}]:
        return False, "model_card_dataset_lineage_missing"
    if data.get("hashes") != [{"alg": "SHA-256", "content": expected["dataset_sha256"]}]:
        return False, "dataset_component_hash_mismatch"
    return True, "bounded_lineage_metadata_matches_observations"


def _security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"}}


def _wait_job(lab):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", JOB, "-o", "json").stdout)
        conditions = job.get("status", {}).get("conditions", [])
        if any(row.get("type") == "Complete" and row.get("status") == "True" for row in conditions):
            return job
        if any(row.get("type") == "Failed" and row.get("status") == "True" for row in conditions):
            lab.block("Training fixture Job failed")
        time.sleep(1)
    lab.block("Training fixture Job did not complete before timeout")


def run(lab):
    dataset_raw = (FIXTURES / "dataset.json").read_bytes()
    config_raw = (FIXTURES / "training-config.json").read_bytes()
    dataset = json.loads(dataset_raw)
    config = json.loads(config_raw)
    cm = lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG, "namespace": NS, "labels": {"saf.control": CONTROL_ID}},
        "immutable": True,
        "data": {"dataset.json": dataset_raw.decode(), "training-config.json": config_raw.decode(),
                 "trainer.py": TRAINER}})
    if not cm.get("metadata", {}).get("uid"):
        lab.block("Kubernetes did not return an immutable fixture ConfigMap identity")
    job_obj = {"apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB, "namespace": NS, "labels": {"saf.control": CONTROL_ID}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "ttlSecondsAfterFinished": 60,
            "template": {"metadata": {"labels": {"job-name": JOB, "saf.control": CONTROL_ID}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "trainer", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent", "command": ["python", "-B", "/fixture/trainer.py"],
                        "env": [{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}],
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": _security(),
                        "volumeMounts": [{"name": "input", "mountPath": "/fixture", "readOnly": True}]}],
                    "volumes": [{"name": "input", "configMap": {"name": CONFIG, "items": [
                        {"key": "dataset.json", "path": "dataset.json"},
                        {"key": "training-config.json", "path": "training-config.json"},
                        {"key": "trainer.py", "path": "trainer.py"}]}}]}}}}
    created = lab.create(job_obj)
    job = _wait_job(lab)
    pod_list = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={JOB}", "-o", "json").stdout)
    pods = pod_list.get("items", [])
    if len(pods) != 1:
        lab.block("Expected exactly one completed Job Pod")
    pod = pods[0]
    container = pod.get("status", {}).get("containerStatuses", [{}])[0]
    terminated = container.get("state", {}).get("terminated", {})
    if terminated.get("exitCode") != 0:
        lab.block("Training fixture did not exit successfully")
    lines = [line for line in lab.kubectl("logs", f"pod/{pod['metadata']['name']}", "-c", "trainer").stdout.splitlines() if line.strip()]
    try:
        receipt = json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Training Job did not emit one valid JSON receipt")
    node_name = pod.get("spec", {}).get("nodeName")
    if not node_name or receipt.get("node_name") != node_name:
        lab.block("Training receipt node name does not match Pod scheduling")
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout).get("items", [])
    matches = [node for node in nodes if node.get("metadata", {}).get("name") == node_name]
    if len(matches) != 1:
        lab.block("Assigned training Node identity could not be resolved")
    node = matches[0]
    node_info = node.get("status", {}).get("nodeInfo", {})
    node_uid = node.get("metadata", {}).get("uid")
    if not node_uid or not node_info.get("kubeletVersion") or not node_info.get("containerRuntimeVersion"):
        lab.block("Assigned Node identity/runtime fields are incomplete")
    actual = {"dataset_sha256": _sha(dataset_raw), "training_config_sha256": _sha(config_raw),
        "model_sha256": receipt.get("model_sha256"), "hyperparameters": config,
        "python_version": receipt.get("python_version"), "job_uid": job.get("metadata", {}).get("uid"),
        "pod_uid": pod.get("metadata", {}).get("uid"), "node_uid": node_uid, "node_name": node_name,
        "kubelet_version": node_info["kubeletVersion"], "container_runtime_version": node_info["containerRuntimeVersion"]}
    if (created.get("metadata", {}).get("uid") != actual["job_uid"] or not actual["pod_uid"]
            or receipt.get("dataset_sha256") != actual["dataset_sha256"]
            or receipt.get("training_config_sha256") != actual["training_config_sha256"]
            or receipt.get("hyperparameters") != config or receipt.get("third_party_dependencies") != []
            or not re.fullmatch(r"\d+\.\d+\.\d+", str(actual["python_version"]))
            or not re.fullmatch(r"[0-9a-f]{64}", str(actual["model_sha256"]))
            or _canonical_hash(receipt["model"]) != actual["model_sha256"]):
        lab.block("Training receipt did not bind the fixed input and actual runtime")
    model_ref = "model-saf-toy-linear-v1"
    data_ref = "dataset-saf-mlbom-toy-v1"
    props = [
        {"name": "saf:dataset:sha256", "value": actual["dataset_sha256"]},
        {"name": "saf:training-config:sha256", "value": actual["training_config_sha256"]},
        {"name": "saf:model:sha256", "value": actual["model_sha256"]},
        {"name": "saf:trainer:name", "value": receipt["trainer_name"]},
        {"name": "saf:trainer:version", "value": receipt["trainer_version"]},
        {"name": "saf:python:version", "value": receipt["python_version"]},
        {"name": "saf:dependencies:third-party-count", "value": str(len(receipt["third_party_dependencies"]))},
        {"name": "saf:hyperparameters:json", "value": json.dumps(config, sort_keys=True, separators=(",", ":"))},
        {"name": "saf:training:image", "value": PYTHON_IMAGE},
        {"name": "saf:fixture:configmap-uid", "value": cm["metadata"]["uid"]},
        {"name": "saf:infrastructure:job-uid", "value": actual["job_uid"]},
        {"name": "saf:infrastructure:pod-uid", "value": actual["pod_uid"]},
        {"name": "saf:infrastructure:node-uid", "value": actual["node_uid"]},
        {"name": "saf:infrastructure:node-name", "value": actual["node_name"]},
        {"name": "saf:infrastructure:kubelet-version", "value": actual["kubelet_version"]},
        {"name": "saf:infrastructure:container-runtime", "value": actual["container_runtime_version"]},
        {"name": "saf:training:model-json", "value": json.dumps(receipt["model"], sort_keys=True, separators=(",", ":"))},
    ]
    bom = {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX",
        "specVersion": "1.7", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
            "lifecycles": [{"phase": "post-build"}],
            "tools": {"components": [{"type": "application", "name": "saf-mlbom-control-case", "version": "1.0.0"}]},
            "component": {"type": "machine-learning-model", "bom-ref": model_ref,
                "name": config["model_id"], "version": "1.0.0", "modelCard": {
                    "modelParameters": {"approach": {"type": "supervised"}, "task": "regression",
                                        "datasets": [{"ref": data_ref}]}},
                "properties": props}},
        "components": [
            {"type": "data", "bom-ref": data_ref, "name": dataset["dataset_id"],
             "data": [{"type": "dataset", "name": dataset["dataset_id"], "classification": "public-synthetic"}],
             "hashes": [{"alg": "SHA-256", "content": actual["dataset_sha256"]}]},
        ],
        "dependencies": [{"ref": model_ref, "dependsOn": [data_ref]}]}
    red_bom = json.loads(json.dumps(bom))
    red_bom["metadata"]["component"]["properties"] = [p for p in props if p["name"] != "saf:dataset:sha256"]
    red, red_reason = _validate_metadata(red_bom, actual)
    lab.check("red", "Metadata validator rejects a BOM without the actual training dataset digest",
              not red and red_reason == "lineage_metadata_missing_or_mismatched",
              {"accepted": red, "reason": red_reason, "missing": "dataset_sha256"})
    green, green_reason = _validate_metadata(bom, actual)
    lab.check("green", "Generated BOM records matching dataset/config/model hashes, hyperparameters, trainer/runtime and infrastructure identity",
              green and green_reason == "bounded_lineage_metadata_matches_observations",
              {"accepted": green, "reason": green_reason,
               "dataset_sha256_matches_fixture": True, "config_sha256_matches_fixture": True,
               "model_sha256_matches_receipt": True, "dependency_count": 0,
               "infrastructure_fields": ["job_uid", "pod_uid", "node_uid", "node_name", "kubelet_version", "container_runtime_version"]})
    positive_ok = (receipt["model"] == {"algorithm": config["algorithm"], "bias": 0.0, "weight": 1.0}
                   and job.get("status", {}).get("succeeded") == 1
                   and pod.get("metadata", {}).get("uid") == actual["pod_uid"]
                   and node_name == receipt["node_name"]
                   and "@sha256:" in PYTHON_IMAGE)
    lab.check("positive", "The deterministic toy model came from the successful restricted Job on the observed Node",
              positive_ok,
              {"job_succeeded": job.get("status", {}).get("succeeded"), "model": receipt["model"],
               "job_uid_matches_create": created.get("metadata", {}).get("uid") == actual["job_uid"],
               "pod_uid_observed": bool(actual["pod_uid"]), "node_uid_observed": bool(actual["node_uid"]),
               "pinned_image": True, "third_party_dependencies": 0})
    generated = lab.evidence / "generated-mlbom.json"
    generated.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    validate_bom(lab, generated, "v1_7")
    evidence = {"control_id": CONTROL_ID, "catalog_revision": "133a8698a45e2b335b51728bf4c62f7bda98d15f",
        "scope": SCOPE, "format_markers": {"bomFormat": bom["bomFormat"], "specVersion": bom["specVersion"]},
        "schema_validation_performed": True,
        "metadata_contract_validation": "case-local lineage checks plus official CycloneDX CLI validation",
        "observed": {"dataset_sha256": actual["dataset_sha256"],
            "training_config_sha256": actual["training_config_sha256"], "model_sha256": actual["model_sha256"],
            "trainer": {"name": receipt["trainer_name"], "version": receipt["trainer_version"],
                        "python_version": receipt["python_version"], "third_party_dependencies": []},
            "hyperparameters": config,
            "infrastructure": {"job_uid": actual["job_uid"], "pod_uid": actual["pod_uid"],
                "node_uid": actual["node_uid"], "node_name": actual["node_name"],
                "kubelet_version": actual["kubelet_version"],
                "container_runtime_version": actual["container_runtime_version"], "image": PYTHON_IMAGE}},
        "checks": lab.checks}
    (lab.evidence / "mlbom-observed.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


VERSION = "v0.33.1"
BINARIES = {
    ("Darwin", "arm64"): ("cyclonedx-osx-arm64", "750c148780154833f6401f9067d08c5a4c31567b6ee3c26c062c3a95c62d741c"),
    ("Darwin", "x86_64"): ("cyclonedx-osx-x64", "0ea92306fc7d7c30ed112a7463781a200585a3bf1cdaf77229181c5aabd1d4b6"),
    ("Linux", "aarch64"): ("cyclonedx-linux-arm64", "b2e9fdf9665ef49868a2ec012171c6e785dcd69745bc5869e53e4f4bfb096a5f"),
    ("Linux", "x86_64"): ("cyclonedx-linux-x64", "bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746"),
}


def validate_bom(lab, document, schema_version):
    platform_key = platform.system(), platform.machine()
    if platform_key not in BINARIES:
        lab.block(f"No pinned CycloneDX CLI for {platform_key}")
    asset_name, digest = BINARIES[platform_key]
    binary = lab.kubeconfig.parent / asset_name
    release = f"https://github.com/CycloneDX/cyclonedx-cli/releases/download/{VERSION}/{asset_name}"
    lab.command("curl", "-fsSL", "--max-time", "75", release, "-o", str(binary), timeout=85)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        lab.block("CycloneDX validator bytes differ from the release digest")
    binary.chmod(0o700)
    result = lab.command(str(binary), "validate", "--input-file", str(Path(document)),
                         "--input-format", "json", "--input-version", schema_version,
                         "--fail-on-errors", timeout=30, allow_failure=True)
    output = result.stdout + result.stderr
    (lab.evidence / "cyclonedx-validation.txt").write_text(output.rstrip("\n") + "\n")
    lab.check("positive", "The pinned CycloneDX CLI validates the generated ML-BOM against the selected schema",
              result.returncode == 0, {"validator": VERSION, "schema": schema_version,
                                       "validation_exit": result.returncode})
