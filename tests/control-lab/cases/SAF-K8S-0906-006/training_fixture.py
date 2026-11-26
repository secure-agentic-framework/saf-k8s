"""Deterministic synthetic ingestion, transformation, training, and release fixture."""
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request

from lineage_crypto import verify as verify_ed25519
from signature_format import canonical, public_key_id

SOURCE = b"cedar=amber\nmaple=blue\nbirch=green\n"
MISMATCH = b"cedar=violet\nmaple=blue\nbirch=green\n"
TRANSFORMED = b"amber cedar\nblue maple\ngreen birch\n"
SOURCE_DIGEST = hashlib.sha256(SOURCE).hexdigest()
TRANSFORMED_DIGEST = hashlib.sha256(TRANSFORMED).hexdigest()
SOURCE_ID = "synthetic-source-v1"
TRANSFORM_ID = "normalize-token-order-v1"
TRAINER_ID = "deterministic-count-model-v1"
PRODUCER_USERS = {
    "source": "system:serviceaccount:saf-test:fixture-lineage-source",
    "transform": "system:serviceaccount:saf-test:fixture-lineage-transform",
    "training": "system:serviceaccount:saf-test:fixture-lineage-training",
}
SIGNATURE_PATHS = {
    "source": "/source-receipt/source.signature.json",
    "transform": "/transform-receipt/transformation.signature.json",
    "training": "/artifact/governed/training.signature.json",
}

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

def sign_receipt(stage):
    token = Path("/identity/token").read_text().strip()
    request = urllib.request.Request(
        os.environ["SIGNER_URL"] + "/sign/" + stage,
        data=b"{}", method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile="/tls-ca/ca.pem")
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            signed = json.load(response)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        raise RuntimeError("fixture identity signer denied or failed") from None
    if signed.get("signed") is not True:
        raise RuntimeError("fixture identity signer refused receipt")
    write(SIGNATURE_PATHS[stage], (json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return True

def verify_receipt(stage):
    signed = load_json(SIGNATURE_PATHS[stage])
    receipt_path = {"source": "/source-receipt/source.json",
                    "transform": "/transform-receipt/transformation.json",
                    "training": "/artifact/governed/training-receipt.json"}[stage]
    public_pem = Path("/trust/public.pem").read_text()
    expected = {"schema": "training-lineage-receipt/v1", "stage": stage,
                "producer": PRODUCER_USERS[stage], "receipt": load_json(receipt_path)}
    try:
        return (signed.get("signed") is True and signed.get("envelope") == expected
                and signed.get("key_id") == public_key_id(public_pem)
                and verify_ed25519(public_pem, __import__("base64").b64decode(
                    signed["signature"], validate=True), canonical(expected)))
    except (KeyError, ValueError, TypeError):
        return False

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
        signed = sign_receipt("source")
        print(json.dumps({"source_sha256": digest(SOURCE), "source_receipt_persisted": True,
                          "producer_signature_written": signed}, sort_keys=True)); return
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
        signed = sign_receipt("transform")
        print(json.dumps({"transformed": True, "output_sha256": digest(output),
                          "producer_signature_written": signed}, sort_keys=True)); return
    if name == "identity-probe":
        try:
            sign_receipt("source")
            denied = False
        except RuntimeError:
            denied = True
        print(json.dumps({"wrong_producer_denied": denied,
                          "signature_created": Path(SIGNATURE_PATHS["source"]).exists()}, sort_keys=True))
        return
    if name == "train" and not os.environ.get("APPROVAL_JSON"):
        print(json.dumps({"decision": "denied", "reason": "approval-absent"}, sort_keys=True)); return
    if name == "train":
        approval = json.loads(os.environ["APPROVAL_JSON"])
        raw = read("/source/ingested.bin")
        source_receipt = load_json("/source-receipt/source.json")
        data = read("/transformed/dataset.bin")
        transform_receipt = load_json("/transform-receipt/transformation.json")
        source_signature_ok = verify_receipt("source")
        transform_signature_ok = verify_receipt("transform")
        checks = {
            "approved_source_digest": approval["source_sha256"] == digest(raw) == source_receipt["source_sha256"],
            "approved_transformed_digest": approval["transformed_sha256"] == digest(data) == transform_receipt["output_sha256"],
            "source_linked": transform_receipt["source_sha256"] == source_receipt["source_sha256"],
            "source_receipt_approval_matches": source_receipt["approval_ref"] == approval["approval_id"],
            "expected_transform": transform_receipt["transform_id"] == TRANSFORM_ID,
            "source_producer_signature": source_signature_ok,
            "transform_producer_signature": transform_signature_ok,
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
        training_signature = sign_receipt("training")
        print(json.dumps({"decision": "trained", "checks": checks, **training,
                          "producer_signature_written": training_signature}, sort_keys=True))
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
        signature_checks = {stage: verify_receipt(stage) for stage in ("source", "transform", "training")}
        checks = {
            "approval_matches_source": approval["source_sha256"] == src["source_sha256"] == trained["source_sha256"],
            "approval_matches_transformed": approval["transformed_sha256"] == trans["output_sha256"] == trained["transformed_sha256"],
            "receipt_digests_match": trained["source_receipt_sha256"] == digest(read("/source-receipt/source.json"))
                and trained["transformation_receipt_sha256"] == digest(read("/transform-receipt/transformation.json")),
            "artifact_digest_matches": trained["artifact_sha256"] == digest(model),
            "approval_id_matches": trained["approval_id"] == approval["approval_id"],
            "all_producer_signatures_valid": all(signature_checks.values()),
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
    if name == "trace-query":
        # Query only release bindings stored on the five case-owned PVCs. The
        # query Job mounts those claims read-only. Validate each stored edge
        # from its bytes before returning bounded predicates.
        root = Path("/artifact")
        records = []
        for binding_path in sorted(root.glob("*/release-binding.json")):
            binding = json.loads(binding_path.read_bytes())
            artifact_path = binding_path.parent / "model.json"
            training_path = binding_path.parent / "training-receipt.json"
            model_bytes = artifact_path.read_bytes()
            training_bytes = training_path.read_bytes()
            source_receipt_bytes = read("/source-receipt/source.json")
            transformation_receipt_bytes = read("/transform-receipt/transformation.json")
            source_bytes = read("/source/ingested.bin")
            transformed_bytes = read("/transformed/dataset.bin")
            source_receipt = json.loads(source_receipt_bytes)
            transformation_receipt = json.loads(transformation_receipt_bytes)
            training = json.loads(training_bytes)
            valid = all((
                digest(model_bytes) == binding.get("artifact_sha256"),
                digest(training_bytes) == binding.get("training_receipt_sha256"),
                digest(source_receipt_bytes) == binding.get("source_receipt_sha256"),
                digest(transformation_receipt_bytes) == binding.get("transformation_receipt_sha256"),
                digest(source_bytes) == source_receipt.get("source_sha256")
                    == transformation_receipt.get("source_sha256")
                    == training.get("source_sha256") == binding.get("source_sha256"),
                digest(transformed_bytes) == transformation_receipt.get("output_sha256")
                    == training.get("transformed_sha256")
                    == binding.get("transformed_sha256"),
                transformation_receipt.get("transform_id") == TRANSFORM_ID,
                source_receipt.get("approval_ref") == binding.get("approval_id"),
                training.get("transformation_receipt_sha256")
                    == digest(transformation_receipt_bytes),
                training.get("source_receipt_sha256") == digest(source_receipt_bytes),
                training.get("artifact_sha256") == digest(model_bytes),
                training.get("approval_id") == binding.get("approval_id"),
                binding.get("training_receipt_sha256") == digest(training_bytes),
                verify_receipt("source"), verify_receipt("transform"), verify_receipt("training"),
            ))
            records.append({"valid": valid, "artifact_sha256": digest(model_bytes),
                            "source_sha256": source_receipt.get("source_sha256"),
                            "transform_id": transformation_receipt.get("transform_id"),
                            "transformed_sha256": transformation_receipt.get("output_sha256")})

        valid_records = [row for row in records if row["valid"]]
        artifact_query = os.environ["TRACE_ARTIFACT_SHA256"]
        source_query = os.environ["TRACE_SOURCE_SHA256"]
        transform_id_query = os.environ["TRACE_TRANSFORM_ID"]
        transformed_query = os.environ["TRACE_TRANSFORMED_SHA256"]
        expected_artifact = os.environ["TRACE_EXPECTED_ARTIFACT_SHA256"]
        forward = [row for row in valid_records if row["artifact_sha256"] == artifact_query]
        reverse_source = [row["artifact_sha256"] for row in valid_records
                          if row["source_sha256"] == source_query]
        reverse_transform = [row["artifact_sha256"] for row in valid_records
                             if row["transform_id"] == transform_id_query
                             and row["transformed_sha256"] == transformed_query]
        ungoverned = [row for row in valid_records
                      if row["source_sha256"] == os.environ["TRACE_UNGOVERNED_SOURCE_SHA256"]]
        unknown = [row for row in valid_records
                   if row["source_sha256"] == os.environ["TRACE_UNKNOWN_SOURCE_SHA256"]]
        print(json.dumps({
            "stored_binding_count": len(records),
            "all_stored_records_validate": bool(records) and len(valid_records) == len(records),
            "all_producer_signatures_valid": bool(records) and len(valid_records) == len(records),
            "forward_artifact_resolved": len(forward) == 1,
            "forward_source_edge_matches": len(forward) == 1
                and forward[0]["source_sha256"] == source_query,
            "forward_transform_edge_matches": len(forward) == 1
                and forward[0]["transform_id"] == transform_id_query
                and forward[0]["transformed_sha256"] == transformed_query,
            "reverse_source_match_count": len(reverse_source),
            "reverse_source_returns_exact_artifact": reverse_source == [expected_artifact],
            "reverse_transform_match_count": len(reverse_transform),
            "reverse_transform_returns_exact_artifact": reverse_transform == [expected_artifact],
            "ungoverned_source_match_count": len(ungoverned),
            "unknown_source_match_count": len(unknown),
        }, sort_keys=True))
        return
    raise SystemExit("unknown fixture operation")

if __name__ == "__main__":
    op(sys.argv[1])
