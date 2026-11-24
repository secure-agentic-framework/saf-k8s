"""Bounded synthetic integrity-to-publication producer and independent reader."""
import hashlib
import contextlib
import io
import json
import sys
from pathlib import Path

import dataset_fixture
import feature_fixture


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _input_record(manifest, manifest_bytes, verification, partition):
    """The exact input read by the existing feature publication gate."""
    return {
        "dataset_id": manifest["dataset_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "partition_merkle_root": verification["merkle_root"],
        "record": {
            **feature_fixture.RECORDS["valid"],
            "features": {
                "signal_mean": sum(partition) / (255 * len(partition)),
                "context_count": verification["partitions"],
            },
        },
    }


def producer(scenario, state, manifest_path):
    state = Path(state)
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes)
    root = state / "datasets" / scenario
    output_dir = state / "published" / scenario
    input_path = state / "inputs" / (scenario + ".json")
    output_path = output_dir / "candidate.json"
    for path in (root, output_dir, input_path.parent):
        path.mkdir(parents=True, exist_ok=True)
    if scenario == "wrong-bytes":
        dataset_fixture.prepare(root, altered=3)
    elif scenario == "missing-partition":
        dataset_fixture.prepare(root, missing=2)
    elif scenario == "approved-clean":
        dataset_fixture.prepare(root)
    else:
        raise ValueError("unknown scenario")

    baseline = dataset_fixture.baseline_accept(root)
    verification = dataset_fixture.verify(root, manifest)
    if not verification["accepted"]:
        emit({"decision": "integrity_rejected", "reason": verification["reason"],
              "scenario": scenario, "unchecked_reader_accepted": baseline["accepted"],
              "publish_input_created": False, "publish_outcome_created": False})
        return

    partition_name = "part-03.bin"
    partition = (root / partition_name).read_bytes()
    expected = manifest["partitions"][partition_name]
    if len(partition) != expected["size"] or hashlib.sha256(partition).hexdigest() != expected["sha256"]:
        raise RuntimeError("Partition changed before consumption")
    observed_input = _input_record(manifest, manifest_bytes, verification, partition)
    input_path.write_text(_canonical(observed_input), encoding="utf-8")
    consumed = json.loads(input_path.read_text(encoding="utf-8"))
    if (consumed != observed_input
            or consumed["manifest_sha256"] != hashlib.sha256(manifest_bytes).hexdigest()
            or consumed["dataset_id"] != manifest["dataset_id"]):
        emit({"decision": "integrity_rejected", "reason": "publication_input_binding",
              "scenario": scenario, "publish_input_created": True,
              "publish_outcome_created": False})
        return

    features, reason = feature_fixture.validate_and_transform(consumed["record"])
    if reason is not None:
        emit({"decision": "feature_rejected", "reason": reason, "scenario": scenario,
              "publish_input_created": True, "publish_outcome_created": False})
        return

    # Only an integrity-verified input accepted by the existing feature gate
    # can create this consumer-visible publication object.
    outcome = {
        "dataset_id": consumed["dataset_id"],
        "manifest_sha256": consumed["manifest_sha256"],
        "partition_merkle_root": verification["merkle_root"],
        "feature": features,
    }
    output_path.write_text(_canonical(outcome), encoding="utf-8")
    emit({"decision": "published", "scenario": scenario,
          "publish_input_created": True, "publish_outcome_created": True})


def reader(scenario, state, manifest_path):
    """Independent read-only consumer; never imports producer decision state."""
    state = Path(state)
    output_path = state / "published" / scenario / "candidate.json"
    input_path = state / "inputs" / (scenario + ".json")
    if scenario != "approved-clean":
        present = output_path.exists()
        emit({"publish_input_present": input_path.exists(), "candidate_present": present,
              "consumer_visible_publish_outcome": present,
              "scenario": scenario})
        return

    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = {
        "dataset_id": manifest["dataset_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "partition_merkle_root": manifest["merkle_root"],
        "feature": {
            **feature_fixture.EXPECTED_OUTPUT["valid"],
            # The independently pinned part-03 fixture consists of byte 68.
            "features": {"signal_mean": 68 / 255, "context_count": 4},
        },
    }
    try:
        observed = output_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        observed = None
    emit({"candidate_present": observed is not None,
          "consumer_visible_publish_outcome": observed is not None,
          "exact_readback": observed == _canonical(expected),
          "scenario": scenario})


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in {"producer", "reader"}:
        raise SystemExit("usage: producer|reader SCENARIO STATE MANIFEST")
    mode, scenario, state, manifest = sys.argv[1:]
    (producer if mode == "producer" else reader)(scenario, state, manifest)
