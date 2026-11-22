"""Send and check inert per-node coverage markers against the private lab sink."""
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SINK = "http://audit-receiver.saf-test.svc:8080/events"


def forward():
    node = os.environ["SOURCE_NODE"]
    marker = {"auditID": f"coverage-{node}", "schema": "saf-k8s-lab/v1", "node": node,
              "kind": "SyntheticNodeAuditEvent", "event": "coverage-canary"}
    request = Request(SINK, data=json.dumps(marker).encode(), method="POST",
                      headers={"Content-Type": "application/json"})
    for _ in range(20):
        try:
            with urlopen(request, timeout=3) as response:
                if response.status == 202:
                    Path("/state/accepted").touch()
                    return
        except (HTTPError, URLError, TimeoutError):
            pass
        time.sleep(1)
    raise RuntimeError("fixture receiver did not accept the scheduled node marker")


def sample():
    expected = set(json.loads(os.environ["EXPECTED_NODES"]))
    with urlopen(SINK, timeout=5) as response:
        markers = json.load(response)
    matched = {
        row["node"] for row in markers
        if row.get("event") == "coverage-canary" and row["auditID"] == f"coverage-{row['node']}"
    }
    observed = {"node_count": len(expected), "received_count": len(expected & matched),
                "missing_count": len(expected - matched), "unexpected_count": len(matched - expected)}
    print(json.dumps(observed, sort_keys=True), flush=True)
    return int(matched != expected)


if __name__ == "__main__":
    if sys.argv[1] == "forward":
        forward()
        time.sleep(3600)
    elif sys.argv[1] == "sample":
        raise SystemExit(sample())
    else:
        raise SystemExit("unknown fixture operation")
