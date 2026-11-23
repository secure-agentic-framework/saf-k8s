"""Verify the release contract for the selected synthetic model revision."""
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import sys

ROOT = Path("/inputs")
MODEL = "model-synthetic-linear-demo"
DEPENDENCY = "dependency-synthetic-linear-kernel"
REVISION = "synthetic-linear-demo/1.0.0"
DATASETS = {"dataset-training": "train.csv", "dataset-validation": "validation.csv"}


def checksum(data):
    return sha256(data).hexdigest()


def model_fields(data):
    _, *rows = data.decode("utf-8").splitlines()
    return dict(row.split("=", 1) for row in rows)


def predict(fields, first, second):
    weight_a, weight_b = (float(value) for value in fields["weights"].split(","))
    return int(weight_a * first + weight_b * second + float(fields["bias"]) > 0)


def accuracy(fields, rows):
    comparisons = [predict(fields, float(row["feature_a"]), float(row["feature_b"])) == int(row["label"])
                   for row in rows]
    return sum(comparisons) / len(comparisons)


def relevant_hash(component):
    return next((item["content"] for item in component.get("hashes", []) if item["alg"] == "SHA-256"), None)


def validate(model, bom):
    if model_fields(model)["revision"] != REVISION:
        return "model-revision-mismatch"
    subject = bom["metadata"]["component"]
    if subject.get("type") != "machine-learning-model" or subject.get("bom-ref") != MODEL:
        return "model-component-mismatch"
    if subject.get("version") != REVISION or relevant_hash(subject) != checksum(model):
        return "model-digest-or-revision-mismatch"
    card = subject.get("modelCard", {})
    parameters = card.get("modelParameters", {})
    considerations = card.get("considerations", {})
    if (not parameters.get("task") or not parameters.get("modelArchitecture")
            or not considerations.get("useCases") or not considerations.get("technicalLimitations")):
        return "required-model-card-fields-missing"
    components = {row["bom-ref"]: row for row in bom["components"]}
    subject_edges = next((row["dependsOn"] for row in bom["dependencies"] if row["ref"] == MODEL), [])
    dependency = components.get(DEPENDENCY, {})
    if dependency.get("version") != "0.1.0" or DEPENDENCY not in subject_edges:
        return "software-dependency-missing"
    dataset_refs = {row.get("bom-ref") for row in parameters.get("datasets", [])}
    for name, file in DATASETS.items():
        if name not in dataset_refs or name not in subject_edges or name not in components:
            return "dataset-reference-missing"
        data = (ROOT / file).read_bytes()
        dataset = components[name]
        rows = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
        records = len(rows)
        if relevant_hash(dataset) != checksum(data):
            return "dataset-digest-mismatch"
        if records <= 0 or {"name": "saf-k8s:rows", "value": str(records)} not in dataset["properties"]:
            return "dataset-row-count-mismatch"
        if file == "validation.csv":
            expected = str(accuracy(model_fields(model), rows))
            observations = card.get("quantitativeAnalysis", {}).get("performanceMetrics", [])
            if {"type": "accuracy", "value": expected, "slice": "synthetic-validation-fixture"} not in observations:
                return "model-card-metric-mismatch"
    return None


def run():
    model = (ROOT / "model.txt").read_bytes()
    if sys.argv[1] != "baseline":
        error = validate(model, json.loads((ROOT / "bom.json").read_text()))
        if error:
            print(json.dumps({"decision": "hold", "reason": error}))
            return 1
    fields = model_fields(model)
    marker = predict(fields, 2, 1)
    print(json.dumps({"decision": "allow", "model_sha256": checksum(model), "marker": marker}))
    return 0


if __name__ == "__main__":
    sys.exit(run())
