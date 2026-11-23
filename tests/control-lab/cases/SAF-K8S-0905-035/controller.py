"""Execute one rollout analysis window and atomically record any route reversal."""
import json
import os
from pathlib import Path
import ssl
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
ROLLBACK = "saf.example/automatic-rollback"
SAMPLES = 4
CUTOFF = 3
SLOW_SECONDS = 0.22


def policy_api(update=None):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    namespace = (ROOT / "namespace").read_text().strip()
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/services/model-route"
    headers = {"Authorization": "Bearer " + (ROOT / "token").read_text().strip()}
    if update is not None:
        headers["Content-Type"] = "application/merge-patch+json"
    tls = ssl.create_default_context(cafile=str(ROOT / "ca.crt"))
    data = json.dumps(update).encode() if update is not None else None
    with urlopen(Request(url, data, headers, method="PATCH" if data else "GET"), context=tls, timeout=6) as result:
        return json.load(result)


def sample():
    start = time.monotonic()
    try:
        with urlopen("http://candidate:8080/infer", timeout=3) as result:
            status, body = result.status, result.read().decode()
    except HTTPError as result:
        status, body = result.code, result.read().decode()
    if body != "candidate" or status not in (200, 503):
        raise RuntimeError("unexpected candidate response")
    return {"status": status, "elapsed_seconds": time.monotonic() - start}


def main():
    route = policy_api()
    if route["spec"]["selector"] != {"app": "candidate"}:
        raise RuntimeError("test window is not armed to the candidate")
    samples = [sample() for _ in range(SAMPLES)]
    errors = sum(row["status"] >= 500 for row in samples)
    slow = sum(row["elapsed_seconds"] >= SLOW_SECONDS for row in samples)
    reason = "error-rate" if errors >= CUTOFF else "latency" if slow >= CUTOFF else "healthy"
    enabled = os.environ["ENABLED"] == "true"
    report = {"reason": reason, "samples": samples, "error_count": errors, "slow_count": slow,
              "enabled": enabled, "rollback": enabled and reason != "healthy"}
    if report["rollback"]:
        policy_api({"metadata": {"resourceVersion": route["metadata"]["resourceVersion"],
                                 "annotations": {ROLLBACK: json.dumps(report, sort_keys=True)}},
                    "spec": {"selector": {"app": "stable"}}})
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
