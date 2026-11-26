"""Reference decision process for a fixed, inert break-glass metadata record.

This is an application-level example. It receives its evaluation instant as
fixture input so the time boundary is deterministic; it is not a clock source,
Kubernetes admission policy, or proof of production enforcement.
"""

from datetime import datetime
import json
import sys


def instant(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("fixture timestamp must be UTC RFC3339")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def decide(payload):
    record = payload["record"]
    request = payload["request"]
    if (request.get("requestId") != record.get("requestId")
            or request.get("targetDigest") != record.get("targetDigest")):
        return {"permitted": False, "reason": "request-mismatch"}
    if record.get("security") != "approved" or record.get("operations") != "approved":
        return {"permitted": False, "reason": "approvals-incomplete"}
    if instant(payload["evaluatedAt"]) >= instant(record["expiresAt"]):
        return {"permitted": False, "reason": "expired"}
    return {"permitted": True, "reason": "approved-unexpired"}


def main():
    payload = json.load(sys.stdin)
    print(json.dumps(decide(payload), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
