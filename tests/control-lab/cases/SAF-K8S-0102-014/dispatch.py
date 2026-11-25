"""Scheduled public-certificate selector; it cannot renew or restart anything."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import time
from urllib.request import Request, urlopen


NAMESPACE = "saf-test"
INPUT = "saf-0102-014-schedule-input"
RECEIPTS = {"saf-0102-014-schedule-not-due", "saf-0102-014-schedule-due"}
ORDER = ("etcd/server", "apiserver-etcd-client", "etcd/peer")
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
JOB_NAME = os.environ["JOB_NAME"]
API = "https://kubernetes.default.svc"
CLOCK_BASIS = "synthetic_expiry_offsets_only"


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
    inventory = json.loads(data["inventory_json"])
    lead = int(data["lead_seconds"])
    decision_at = int(data["decision_at_epoch"])
    receipt_name = data["receipt_name"]
    if receipt_name not in RECEIPTS or data.get("clock_basis") != CLOCK_BASIS:
        raise RuntimeError("receipt or decision clock is outside the fixture contract")
    if lead <= 0 or not isinstance(inventory, list) or len(inventory) != len(ORDER):
        raise RuntimeError("invalid fixture inventory or lead")

    by_role = {}
    for row in inventory:
        role = row.get("role")
        fingerprint = row.get("sha256_fingerprint")
        before, after = int(row["not_before_epoch"]), int(row["not_after_epoch"])
        if (role not in ORDER or role in by_role or before >= after
                or len(fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in fingerprint)):
            raise RuntimeError("invalid public leaf record")
        by_role[role] = {"role": role, "sha256_fingerprint": fingerprint,
                         "not_before_epoch": before, "not_after_epoch": after}
    if set(by_role) != set(ORDER):
        raise RuntimeError("fixture inventory does not cover exact role set")

    canonical_inventory = [by_role[role] for role in ORDER]
    digest = hashlib.sha256(json.dumps(canonical_inventory, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    selected = [role for role in ORDER
                if by_role[role]["not_before_epoch"] <= decision_at
                < by_role[role]["not_after_epoch"]
                and by_role[role]["not_after_epoch"] - decision_at <= lead]
    selected_receipts = [by_role[role] for role in selected]
    due = bool(selected)
    result = {
        "decision": "renewal_request" if due else "not_due",
        "selected_roles_json": json.dumps(selected, separators=(",", ":")),
        "selected_receipts_json": json.dumps(selected_receipts, sort_keys=True,
                                              separators=(",", ":")),
        "inventory_sha256": digest,
        "lead_seconds": str(lead),
        "decision_at_epoch": str(decision_at),
        "clock_basis": CLOCK_BASIS,
        "observed_at_epoch": str(int(time.time())),
        "job_name": JOB_NAME,
        "request_id": digest + ":" + str(decision_at) if due else "",
    }
    request(prefix + receipt_name, method="PATCH", body={"data": result})
    print("decision=" + result["decision"])


if __name__ == "__main__":
    main()
