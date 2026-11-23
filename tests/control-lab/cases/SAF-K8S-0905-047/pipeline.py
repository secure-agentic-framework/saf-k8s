"""Deterministic training and package steps, plus in-toto statement generation."""
import base64
import hashlib
import json
from pathlib import Path
import sys

STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATE = "https://slsa.dev/provenance/v1"
TYPE = b"application/vnd.in-toto+json"
BUILD_BASE = "https://saf-k8s.example.test/pipeline/v1/"
BUILDER = "https://saf-k8s.example.test/disposable-kind-job"
TRAIN_INPUT = "training-input-manifest.json"
INTERMEDIATE = "training-intermediate.json"
MODEL = "model.json"
PACKAGE = "model-package.json"
PROVENANCE = "packaging-record.json"
STEPS = {
    "training": ((TRAIN_INPUT,), (INTERMEDIATE, MODEL)),
    "packaging": ((TRAIN_INPUT, INTERMEDIATE, MODEL), (PACKAGE, PROVENANCE)),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pae(raw):
    return b"DSSEv1 %d %s %d " % (len(TYPE), TYPE, len(raw)) + raw


def read_inputs(step):
    return {name: Path("/input", name).read_bytes() for name in STEPS[step][0]}


def training(inputs):
    rows = json.loads(inputs[TRAIN_INPUT])["records"]
    xs, ys = zip(*rows)
    mean_x, mean_y = sum(xs) / len(xs), sum(ys) / len(ys)
    centered_x = [x - mean_x for x in xs]
    weight = sum(x * (y - mean_y) for x, y in zip(centered_x, ys)) / sum(x*x for x in centered_x)
    parameters = {"weight": weight, "bias": mean_y - weight * mean_x}
    model = {"algorithm": "closed-form-linear-regression", "parameters": parameters}
    return {INTERMEDIATE: canonical(parameters), MODEL: canonical(model)}


def packaging(inputs):
    package = canonical({"format": "saf-toy-model-package-v1", "model": json.loads(inputs[MODEL]),
                         "training_manifest_sha256": sha(inputs[TRAIN_INPUT])})
    record = {"inputs": {name: sha(raw) for name, raw in inputs.items()}, "package_sha256": sha(package)}
    return {PACKAGE: package, PROVENANCE: canonical(record)}


def statement(step, inputs, outputs):
    return {
        "_type": STATEMENT,
        "subject": [{"name": name, "digest": {"sha256": sha(raw)}} for name, raw in outputs.items()],
        "predicateType": PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_BASE + step,
                "externalParameters": {"fixture": "SAF-K8S-0905-047", "step": step},
                "internalParameters": {},
                "resolvedDependencies": [{"uri": "urn:saf-fixture:" + name, "digest": {"sha256": sha(raw)}}
                                         for name, raw in inputs.items()],
            },
            "runDetails": {"builder": {"id": BUILDER}, "metadata": {}, "byproducts": []},
        },
    }


def attest():
    for step, (materials, products) in STEPS.items():
        inputs = {name: Path("/input", name).read_bytes() for name in materials}
        outputs = {name: Path("/input", name).read_bytes() for name in products}
        payload = canonical(statement(step, inputs, outputs))
        Path("/work", f"{step}.json").write_bytes(payload)
        Path("/work", f"{step}.pae").write_bytes(pae(payload))


def main(step):
    if step == "attest":
        attest()
        return
    inputs = read_inputs(step)
    outputs = training(inputs) if step == "training" else packaging(inputs)
    print(json.dumps({"inputs": {name: sha(raw) for name, raw in inputs.items()},
                      "outputs": {name: base64.b64encode(raw).decode() for name, raw in outputs.items()}}))


if __name__ == "__main__":
    main(sys.argv[1])
