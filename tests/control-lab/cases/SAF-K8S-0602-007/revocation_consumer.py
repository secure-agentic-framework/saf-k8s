"""Reference decision wrapper that binds revocation metadata to one approval."""
import hashlib
import json
import sys

from expiry_consumer import decide as expiry_decision


def decide(payload):
    record = payload["record"]
    revocation = payload["revocation"]
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    fingerprint = hashlib.sha256(canonical).hexdigest()
    if (revocation.get("approvalFingerprint") != fingerprint
            or any(revocation.get(key) != record.get(key)
                   for key in ("requestId", "targetDigest", "expiresAt"))):
        return {"permitted": False, "reason": "revocation-binding-mismatch"}
    if revocation.get("state") == "revoked":
        return {"permitted": False, "reason": "revoked"}
    if revocation.get("state") != "active":
        return {"permitted": False, "reason": "invalid-revocation-state"}
    return expiry_decision(payload)


def main():
    payload = json.load(sys.stdin)
    print(json.dumps(decide(payload), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
