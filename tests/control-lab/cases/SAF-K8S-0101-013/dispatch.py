"""Namespaced scheduled expiry decision; deliberately cannot renew certificates."""
import json
import os
from pathlib import Path
import ssl
import time
from urllib.request import Request, urlopen


NAMESPACE = "saf-test"
INPUT = "saf-0101-013-schedule-input"
RECEIPTS = {"saf-0101-013-schedule-not-due", "saf-0101-013-schedule-due"}
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
JOB_NAME = os.environ["JOB_NAME"]
API = "https://kubernetes.default.svc"


def request(path, method="GET", body=None):
    token = TOKEN.read_text(encoding="ascii").strip()
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = Request(API + path, data=payload, method=method, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/merge-patch+json",
    })
    context = ssl.create_default_context(cafile=CA)
    with urlopen(req, context=context, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("unexpected API status")
        return response.read()


def main():
    prefix = f"/api/v1/namespaces/{NAMESPACE}/configmaps/"
    source = json.loads(request(prefix + INPUT))
    data = source.get("data", {})
    expiry = int(data["not_after_epoch"])
    lead = int(data["lead_seconds"])
    fingerprint = data["leaf_sha256"]
    receipt = data["receipt_name"]
    if receipt not in RECEIPTS:
        raise RuntimeError("receipt name is outside the fixture allow-list")
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        raise RuntimeError("invalid public leaf fingerprint")
    now = int(time.time())
    due = now < expiry and expiry - now <= lead
    result = {
        "decision": "renewal_request" if due else "not_due",
        "leaf_sha256": fingerprint,
        "not_after_epoch": str(expiry),
        "lead_seconds": str(lead),
        "observed_at_epoch": str(now),
        "job_name": JOB_NAME,
        "request_id": fingerprint + ":" + str(expiry) if due else "",
    }
    request(prefix + receipt, method="PATCH", body={"data": result})
    print("decision=" + result["decision"])


if __name__ == "__main__":
    main()
