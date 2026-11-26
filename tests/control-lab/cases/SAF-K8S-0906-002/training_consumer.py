"""Fixed-input downstream consumer gate; no model or data bytes are emitted."""
import json
import sys
from pathlib import Path

from dataset_fixture import CHUNK_SIZE, verify


def consume(root, manifest):
    """A bounded intake stand-in that actually streams accepted files."""
    total = 0
    count = 0
    for name in sorted(manifest["partitions"]):
        with open(Path(root) / name, "rb") as stream:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
        count += 1
    return {"consumed_bytes": total, "consumed_partitions": count}


def run(root, manifest_path):
    root = Path(root)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    decision = verify(root, manifest)
    if not decision["accepted"]:
        print(json.dumps({
            "decision": "denied",
            "consumer_started": False,
            "consumed_bytes": 0,
            "consumed_partitions": 0,
            "reason": decision["reason"],
        }, sort_keys=True, separators=(",", ":")))
        return

    # This second read is the actual consumer phase. It only runs after the
    # complete inventory, byte length, digest and Merkle checks succeeded.
    observed = consume(root, manifest)
    print(json.dumps({
        "decision": "accepted",
        "consumer_started": True,
        "dataset_id": manifest["dataset_id"],
        "manifest_merkle_root": manifest["merkle_root"],
        **observed,
    }, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('{"error":"usage"}')
        raise SystemExit(2)
    run(sys.argv[1], sys.argv[2])
