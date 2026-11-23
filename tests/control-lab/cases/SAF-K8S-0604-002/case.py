"""Validate CycloneDX schema and release the verified synthetic model in Kind."""
from copy import deepcopy
import importlib.util
import io
import csv
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
CYCLONEDX = ("docker.io/cyclonedx/cyclonedx-cli:0.31.0@sha256:"
             "01c713f12cf5072fbe8f782fb81f4191efd6fff89c534a3e6d6858e05675baf9")
SCOPE = (
    "Generate and validate a CycloneDX 1.7 inventory for a harmless deterministic model in a "
    "disposable Kind cluster. The release Job checks the model and dataset hashes, model-card "
    "fields and dependency graph. Actual publisher custody, training history, production "
    "data rights and regulatory obligations require independent evidence."
)
spec = importlib.util.spec_from_file_location("mlbom_inventory", HERE / "validate_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def hashes(data):
    return [{"alg": "SHA-256", "content": inventory.checksum(data)}]


def generate(inputs):
    fields = inventory.model_fields(inputs["model.txt"])
    subject = {"type": "machine-learning-model", "bom-ref": inventory.MODEL, "name": fields["model"],
               "version": fields["revision"], "hashes": hashes(inputs["model.txt"]),
               "modelCard": json.loads((HERE / "fixtures" / "card.json").read_text())}
    validation_rows = csv.DictReader(io.StringIO(inputs["validation.csv"].decode("utf-8")))
    accuracy = inventory.accuracy(fields, validation_rows)
    subject["modelCard"]["quantitativeAnalysis"] = {"performanceMetrics": [
        {"type": "accuracy", "value": str(accuracy), "slice": "synthetic-validation-fixture"}
    ]}
    dependency = {"type": "library", "bom-ref": inventory.DEPENDENCY, "name": "synthetic-linear-kernel",
                  "version": "0.1.0", "description": "Fixture-only dependency declaration"}
    components = [dependency]
    for ref, file in inventory.DATASETS.items():
        text = inputs[file].decode("utf-8")
        rows = len(list(csv.DictReader(io.StringIO(text))))
        components.append({"type": "data", "bom-ref": ref, "name": ref, "version": "r1",
                           "data": [{"type": "dataset", "name": file}], "hashes": hashes(inputs[file]),
                           "properties": [{"name": "saf-k8s:rows", "value": str(rows)}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "metadata": {"component": subject},
            "components": components, "dependencies": [
                {"ref": inventory.MODEL, "dependsOn": [item["bom-ref"] for item in components]},
                *({"ref": item["bom-ref"], "dependsOn": []} for item in components),
            ]}


def schema(lab, name, bom):
    path = lab.evidence / (name + ".json")
    path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    result = lab.command(
        "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--cap-drop=ALL",
        "--volume", f"{path}:/input.json:ro", CYCLONEDX, "validate", "--input-file", "/input.json",
        "--input-format", "json", "--input-version", "v1_7", "--fail-on-errors", timeout=175,
        allow_failure=True,
    )
    return result.returncode, result.stdout + result.stderr


def create_input(lab, name, inputs):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": inputs})


def execute(lab, name, inputs, *, baseline=False, published=False):
    mode = "baseline" if baseline else "verify"
    if not published:
        create_input(lab, name, inputs)
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 100, "template": {
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [{
                "name": "review", "image": IMAGE, "command": ["python", "-B", "/inputs/validate.py", mode],
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                    "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "inputs", "mountPath": "/inputs", "readOnly": True}],
            }], "volumes": [{"name": "inputs", "configMap": {"name": name}}]},
        }},
    })
    deadline = time.monotonic() + 108
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        terminal = next((row["type"] for row in job.get("status", {}).get("conditions", [])
                         if row["status"] == "True" and row["type"] in {"Complete", "Failed"}), None)
        if terminal:
            result = lab.kubectl("logs", f"job/{name}", allow_failure=True)
            if result.returncode == 0 and result.stdout.strip():
                return terminal, json.loads(result.stdout)
        time.sleep(1.5)
    lab.block(f"Fixture Job {name} did not produce a release decision")


def run(lab):
    inputs = {path.name: path.read_bytes() for path in (HERE / "fixtures").glob("*")
              if path.suffix in {".txt", ".csv"}}
    bom = generate(inputs)
    readable = {file: data.decode("utf-8") for file, data in inputs.items()}
    readable["validate.py"] = (HERE / "validate_inventory.py").read_text()
    valid_json = json.dumps(bom, sort_keys=True)
    model_digest = inventory.checksum(inputs["model.txt"])
    allowed = {"decision": "allow", "model_sha256": model_digest, "marker": 1}

    ungated = execute(lab, "mlbom-before", readable, baseline=True)
    lab.check("red", "Without the release check, the same model executes without an inventory",
              ungated == ("Complete", allowed), {"executed_without_inventory": ungated == ("Complete", allowed)})

    malformed = deepcopy(bom)
    malformed["metadata"]["component"]["modelCard"]["modelParameters"]["properties"] = []
    invalid_schema, message = schema(lab, "schema-negative", malformed)
    valid_schema, _ = schema(lab, "generated-mlbom", bom)
    bad_field_rejected = invalid_schema == 1 and "modelParameters/properties" in message
    lab.check("green", "Pinned CycloneDX validates the generated 1.7 BOM and rejects a field in the wrong location",
              valid_schema == 0 and bad_field_rejected, {"cyclonedx_1_7_valid": valid_schema == 0,
                                                        "schema_negative_rejected": bad_field_rejected})

    changed = deepcopy(bom)
    changed["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
    missing_edge = deepcopy(bom)
    missing_edge["dependencies"][0]["dependsOn"].remove(inventory.DEPENDENCY)
    mutated_data = {**readable, "bom.json": valid_json, "train.csv": readable["train.csv"] + "0,0,0\n"}
    bad_artifact = execute(lab, "mlbom-wrong-model", {**readable, "bom.json": json.dumps(changed)})
    bad_graph = execute(lab, "mlbom-missing-edge", {**readable, "bom.json": json.dumps(missing_edge)})
    bad_data = execute(lab, "mlbom-changed-dataset", mutated_data)
    expected_failures = [(bad_artifact, "model-digest-or-revision-mismatch"),
                         (bad_graph, "software-dependency-missing"), (bad_data, "dataset-digest-mismatch")]
    blocked = {reason: observed == ("Failed", {"decision": "hold", "reason": reason})
               for observed, reason in expected_failures}
    absent = lab.kubectl("get", "configmap", "mlbom-released", allow_failure=True)
    release_is_absent = absent.returncode != 0 and "(NotFound)" in absent.stderr
    lab.check("green", "Kind release checks hold model digest, dependency and dataset mismatches for distinct reasons",
              all(blocked.values()) and release_is_absent, {**blocked, "release_record_absent": release_is_absent})

    approved = {**readable, "bom.json": valid_json}
    checked = execute(lab, "mlbom-approved", approved)
    if checked != ("Complete", allowed):
        lab.block("The exact model revision and inventory did not pass release verification")
    create_input(lab, "mlbom-released", approved)
    retrievable = json.loads(lab.kubectl("get", "configmap", "mlbom-released", "-o", "json").stdout)
    consumed = execute(lab, "mlbom-released", approved, published=True)
    retained = retrievable["immutable"] is True and retrievable["data"] == approved
    lab.check("positive", "The released record retains the exact verified data and its Job executes the bound model",
              retained and consumed == ("Complete", allowed),
              {"release_bytes_retained": retained, "verified_model_consumed": consumed == ("Complete", allowed)})
