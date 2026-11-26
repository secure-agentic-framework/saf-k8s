"""Small deterministic streaming integrity fixture; all content is synthetic."""
import hashlib
import json
import shutil
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

DATASET_ID = "synthetic-approved-v1"
PARTITION_COUNT = 4
PARTITION_SIZE = 4096
CHUNK_SIZE = 257
MAX_WORKERS = 2
MAX_OUTPUT_PARTITIONS = 4


def emit(obj):
    print(json.dumps(obj, sort_keys=True, separators=(",", ":")))


def expected_bytes(index):
    return bytes((65 + index,)) * PARTITION_SIZE


def prepare(root, altered=None, missing=None):
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for index in range(PARTITION_COUNT):
        if index == missing:
            continue
        value = expected_bytes(index)
        if index == altered:
            # Fixed benign change: no payload, exploit, or external input.
            value = bytes((90,)) * PARTITION_SIZE
        (root / f"part-{index:02d}.bin").write_bytes(value)


def _stream_hash(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def merkle_root(entries):
    leaves = [
        hashlib.sha256(b"\x00" + json.dumps([name, size, digest],
                       separators=(",", ":")).encode()).digest()
        for name, (size, digest) in sorted(entries.items())
    ]

    def fold(nodes):
        if len(nodes) == 1:
            return nodes[0]
        split = 1 << ((len(nodes) - 1).bit_length() - 1)
        return hashlib.sha256(b"\x01" + fold(nodes[:split]) + fold(nodes[split:])).digest()

    if not leaves:
        raise ValueError("manifest has no partitions")
    return fold(leaves).hex()


def verify(root, manifest):
    """Check exact partition inventory and stream/hash at most two files at once."""
    root = Path(root)
    entries = manifest["partitions"]
    expected_names = set(entries)
    children = list(root.iterdir())
    actual_names = {item.name for item in children if not item.is_symlink() and item.is_file()}
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if (missing or unexpected or len(children) != len(actual_names)
            or manifest.get("dataset_id") != DATASET_ID):
        return {"accepted": False, "reason": "inventory_or_dataset_id", "partitions": 0,
                "max_workers": MAX_WORKERS}

    names = sorted(expected_names)
    results = {}
    mismatch = False
    next_index = 0
    pending = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        while next_index < min(MAX_WORKERS, len(names)):
            name = names[next_index]
            pending[pool.submit(_stream_hash, root / name)] = name
            next_index += 1
        while pending:
            completed, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in completed:
                name = pending.pop(future)
                size, digest = results[name] = future.result()
                expected = entries[name]
                if size != expected["size"] or digest != expected["sha256"]:
                    mismatch = True
                if next_index < len(names):
                    name = names[next_index]
                    pending[pool.submit(_stream_hash, root / name)] = name
                    next_index += 1
    if mismatch:
        return {"accepted": False, "reason": "digest_or_size_mismatch",
                "partitions": len(expected_names), "max_workers": MAX_WORKERS}
    observed_root = merkle_root(results)
    if observed_root != manifest["merkle_root"]:
        return {"accepted": False, "reason": "merkle_root_mismatch",
                "partitions": len(expected_names), "max_workers": MAX_WORKERS}
    return {"accepted": True, "reason": "verified", "merkle_root": observed_root, "partitions": len(expected_names),
            "max_workers": MAX_WORKERS,
            "output_partition_count": min(len(expected_names), MAX_OUTPUT_PARTITIONS)}


def baseline_accept(root):
    """Intentional baseline: stream all present files with no trusted comparison."""
    total = 0
    count = 0
    for path in sorted(Path(root).glob("*.bin")):
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
        count += 1
    return {"accepted": count > 0, "partitions": count, "bytes": total}


def run(root, manifest_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    observations = {}

    prepare(root, altered=3)
    base = baseline_accept(root)
    checked = verify(root, manifest)
    observations["red"] = {
        "baseline_accepted_deterministic_change": base["accepted"],
        "baseline_partition_count": base["partitions"],
        "governed_denied_change": not checked["accepted"],
    }

    prepare(root, missing=2)
    checked_missing = verify(root, manifest)
    observations["missing"] = {
        "governed_denied_missing_partition": not checked_missing["accepted"],
        "reason": checked_missing["reason"],
    }

    prepare(root)
    bad_root = verify(root, {**manifest, "merkle_root": "0" * 64})
    observations["missing"]["governed_denied_wrong_root"] = (
        not bad_root["accepted"] and bad_root["reason"] == "merkle_root_mismatch"
    )
    approved = verify(root, manifest)
    observations["positive"] = {
        "approved_dataset_id": manifest["dataset_id"],
        "approved_dataset_accepted": approved["accepted"],
        "partition_count": approved["partitions"],
        "max_parallel_workers": approved["max_workers"],
        "bounded_output_partitions": approved.get("output_partition_count"),
        "stream_chunk_bytes": CHUNK_SIZE,
        "merkle_root": approved.get("merkle_root"),
    }
    # Stage a second approved copy and a fixed altered near-miss for separate
    # read-only Kubernetes consumer Jobs. These are outside the verifier's
    # `segments/` inventory and never alter the original three assertions.
    prepare(Path(root).parent / "consumer-approved")
    prepare(Path(root).parent / "consumer-altered", altered=3)
    emit(observations)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        emit({"error": "usage"})
        raise SystemExit(2)
    run(sys.argv[1], sys.argv[2])
