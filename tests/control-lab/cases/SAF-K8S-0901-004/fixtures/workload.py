"""Verify one inert, fixture-only snapshot mounted into a Kubernetes Job."""
import hashlib
import json
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 5 or sys.argv[1] != "verify":
        print(json.dumps({"result": "invalid-invocation"}, sort_keys=True))
        return 64
    _, _, snapshot_path, digest_path, expected = sys.argv
    raw = Path(snapshot_path).read_bytes()
    recorded = Path(digest_path).read_text(encoding="ascii").strip()
    actual = hashlib.sha256(raw).hexdigest()
    ok = actual == expected == recorded
    try:
        document = json.loads(raw)
        snapshot_id = document["snapshot_id"]
    except (json.JSONDecodeError, KeyError, TypeError):
        snapshot_id = "invalid-fixture"
        ok = False
    print(json.dumps({
        "actual_sha256": actual,
        "expected_sha256": expected,
        "recorded_sha256_matches": recorded == expected,
        "result": "verified" if ok else "digest-mismatch",
        "snapshot_id": snapshot_id,
    }, sort_keys=True))
    return 0 if ok else 23


if __name__ == "__main__":
    raise SystemExit(main())
