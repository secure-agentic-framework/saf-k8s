"""Deterministic synthetic ingestion, transformation, training, and release fixture."""
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import sys

SOURCE = b"cedar=amber\nmaple=blue\nbirch=green\n"
MISMATCH = b"cedar=violet\nmaple=blue\nbirch=green\n"
TRANSFORMED = b"amber cedar\nblue maple\ngreen birch\n"
SOURCE_DIGEST = hashlib.sha256(SOURCE).hexdigest()
TRANSFORMED_DIGEST = hashlib.sha256(TRANSFORMED).hexdigest()
SOURCE_ID = "synthetic-source-v1"
TRANSFORM_ID = "normalize-token-order-v1"
TRAINER_ID = "deterministic-count-model-v1"

def digest(value):
    return hashlib.sha256(value).hexdigest()

def write(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)

def read(path):
    return Path(path).read_bytes()

def receipt(path, value):
    write(path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())

def load_json(path):
    return json.loads(read(path))

def op(name):
    if name == "bootstrap":
        print(json.dumps({"consumer_created": True}, sort_keys=True)); return
    if name == "baseline":
        data = MISMATCH
        model = {"algorithm": TRAINER_ID, "input_sha256": digest(data),
                 "synthetic_counts": {"blue": 1, "green": 1, "violet": 1}}
        write("/artifact/baseline/model.json", (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode())
        receipt("/artifact/baseline/training-receipt.json", {
            "mode": "ungoverned-comparison", "source_receipt": None,
            "transformation_receipt": None, "input_sha256": digest(data),
            "artifact_sha256": digest(read("/artifact/baseline/model.json"))})
        print(json.dumps({"accepted_without_linkage": True, "read_mismatched_benign_fixture": True,
                          "input_sha256": digest(data)}, sort_keys=True)); return
    if name == "ingest":
        write("/source/ingested.bin", SOURCE)
        receipt("/source-receipt/source.json", {"source_id": SOURCE_ID,
            "source_sha256": digest(SOURCE), "bytes": len(SOURCE),
            "approval_ref": "synthetic-approval-v1"})
        print(json.dumps({"source_sha256": digest(SOURCE), "source_receipt_persisted": True}, sort_keys=True)); return
    if name == "write-mismatched-receipt":
        path = "/transform-receipt/transformation.json"
        current = load_json(path)
        receipt(path, {**current, "source_sha256": digest(MISMATCH)})
        print(json.dumps({"mismatched_receipt_persisted": True}, sort_keys=True))
        return
    if name == "transform":
        raw = read("/source/ingested.bin")
        sr = load_json("/source-receipt/source.json")
        if digest(raw) != sr["source_sha256"]:
            print(json.dumps({"transformed": False, "decision": "source-receipt-mismatch"}, sort_keys=True)); return
        if raw != SOURCE:
            print(json.dumps({"transformed": False, "decision": "source-not-approved-fixture"}, sort_keys=True)); return
        pairs = [tuple(row.split("=")) for row in raw.decode().splitlines()]
        output = "".join(f"{color} {tree}\n" for tree, color in sorted(
            pairs, key=lambda pair: pair[1])).encode()
        write("/transformed/dataset.bin", output)
        receipt("/transform-receipt/transformation.json", {
            "transform_id": TRANSFORM_ID, "source_sha256": digest(raw),
            "output_sha256": digest(output), "output_bytes": len(output)})
        print(json.dumps({"transformed": True, "output_sha256": digest(output)}, sort_keys=True)); return
    if name == "train" and not os.environ.get("APPROVAL_JSON"):
        print(json.dumps({"decision": "denied", "reason": "approval-absent"}, sort_keys=True)); return
    if name == "train":
        approval = json.loads(os.environ["APPROVAL_JSON"])
        raw = read("/source/ingested.bin")
        source_receipt = load_json("/source-receipt/source.json")
        data = read("/transformed/dataset.bin")
        transform_receipt = load_json("/transform-receipt/transformation.json")
        checks = {
            "approved_source_digest": approval["source_sha256"] == digest(raw) == source_receipt["source_sha256"],
            "approved_transformed_digest": approval["transformed_sha256"] == digest(data) == transform_receipt["output_sha256"],
            "source_linked": transform_receipt["source_sha256"] == source_receipt["source_sha256"],
            "source_receipt_approval_matches": source_receipt["approval_ref"] == approval["approval_id"],
            "expected_transform": transform_receipt["transform_id"] == TRANSFORM_ID,
        }
        if not all(checks.values()):
            print(json.dumps({"decision": "denied", "checks": checks, "artifact_created": False}, sort_keys=True)); return
        counts = Counter(row.split()[0] for row in data.decode().splitlines())
        model = {"algorithm": TRAINER_ID, "source_sha256": digest(raw),
                 "transformed_sha256": digest(data), "synthetic_counts": dict(counts)}
        model_bytes = (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode()
        write("/artifact/governed/model.json", model_bytes)
        training = {
            "trainer_id": TRAINER_ID, "source_sha256": digest(raw),
            "source_receipt_sha256": digest(read("/source-receipt/source.json")),
            "transformed_sha256": digest(data),
            "transformation_receipt_sha256": digest(read("/transform-receipt/transformation.json")),
            "approval_id": approval["approval_id"], "artifact_sha256": digest(model_bytes),
        }
        receipt("/artifact/governed/training-receipt.json", training)
        print(json.dumps({"decision": "trained", "checks": checks, **training}, sort_keys=True))
        return
    if name == "release" and not os.environ.get("APPROVAL_JSON"):
        model_exists = Path("/artifact/governed/model.json").exists()
        binding_exists = Path("/artifact/governed/release-binding.json").exists()
        print(json.dumps({"decision": "denied", "reason": "approval-absent",
                          "model_exists_before_release": model_exists,
                          "release_binding_created": binding_exists}, sort_keys=True)); return
    if name == "inspect-denial":
        model_exists = Path("/artifact/governed/model.json").exists()
        binding_exists = Path("/artifact/governed/release-binding.json").exists()
        print(json.dumps({"governed_model_absent": not model_exists,
                          "release_binding_absent": not binding_exists}, sort_keys=True)); return
    if name == "release":
        approval = json.loads(os.environ["APPROVAL_JSON"])
        model = read("/artifact/governed/model.json")
        trained = load_json("/artifact/governed/training-receipt.json")
        src = load_json("/source-receipt/source.json")
        trans = load_json("/transform-receipt/transformation.json")
        checks = {
            "approval_matches_source": approval["source_sha256"] == src["source_sha256"] == trained["source_sha256"],
            "approval_matches_transformed": approval["transformed_sha256"] == trans["output_sha256"] == trained["transformed_sha256"],
            "receipt_digests_match": trained["source_receipt_sha256"] == digest(read("/source-receipt/source.json"))
                and trained["transformation_receipt_sha256"] == digest(read("/transform-receipt/transformation.json")),
            "artifact_digest_matches": trained["artifact_sha256"] == digest(model),
            "approval_id_matches": trained["approval_id"] == approval["approval_id"],
        }
        if not all(checks.values()):
            print(json.dumps({"decision": "denied", "checks": checks,
                              "release_binding_created": False}, sort_keys=True)); return
        binding = {
            "artifact_sha256": digest(model), "training_receipt_sha256": digest(read("/artifact/governed/training-receipt.json")),
            "source_sha256": src["source_sha256"], "transformed_sha256": trans["output_sha256"],
            "source_receipt_sha256": trained["source_receipt_sha256"],
            "transformation_receipt_sha256": trained["transformation_receipt_sha256"],
            "approval_id": approval["approval_id"]}
        receipt("/artifact/governed/release-binding.json", binding)
        print(json.dumps({"decision": "released", "checks": checks,
                          "release_binding_created": True, "binding": binding}, sort_keys=True)); return
    raise SystemExit("unknown fixture operation")

if __name__ == "__main__":
    op(sys.argv[1])
