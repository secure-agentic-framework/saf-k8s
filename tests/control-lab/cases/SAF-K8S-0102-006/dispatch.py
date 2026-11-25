"""Bounded scheduler Job: read one synthetic plan, optionally rewrite owned markers."""
import json
import os
from pathlib import Path
import ssl
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

NAMESPACE = "saf-test"
GROUP = "rotation.saf.example"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"
JOB_NAME = os.environ["JOB_NAME"]
PLAN_NAME = os.environ["PLAN_NAME"]
RECEIPT_NAME = os.environ["RECEIPT_NAME"]
EXPECTED = ["pre-rotation", "rollback-write", "fixture-backup"]


def request(path, method="GET", body=None, content_type="application/json"):
    token = TOKEN.read_text(encoding="ascii").strip()
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = Request(API + path, data=payload, method=method, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": content_type,
    })
    context = ssl.create_default_context(cafile=CA)
    with urlopen(req, context=context, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("unexpected API status")
        raw = response.read(65536)
    return json.loads(raw) if raw else {}


def main():
    cm_prefix = f"/api/v1/namespaces/{NAMESPACE}/configmaps/"
    plan = request(cm_prefix + quote(PLAN_NAME, safe=""))
    data = plan.get("data", {})
    if (data.get("approval_id") != "fixture-approval-006"
            or data.get("approver") != "fixture-approver"
            or data.get("executor") != "fixture-runner"):
        raise RuntimeError("synthetic plan approval was invalid")
    inventory = json.loads(data.get("inventory", "[]"))
    if inventory != EXPECTED:
        raise RuntimeError("synthetic plan inventory did not match the exact allowlist")
    now = int(time.time())
    valid_until = int(data.get("approval_valid_until_epoch", "0"))
    decision = "due" if now >= int(data.get("due_after_epoch", "0")) else "not-due"
    if valid_until <= now:
        decision = "not-due"
    patched = []
    if decision == "due":
        for name in inventory:
            resource_path = (f"/apis/{GROUP}/v1/namespaces/{NAMESPACE}/rotationmarkers/"
                             + quote(name, safe=""))
            request(resource_path, method="PATCH",
                    body={"metadata": {"annotations": {
                        "saf.example/rotation-plan": data["generation"],
                        "saf.example/rotation-trigger": JOB_NAME,
                    }}}, content_type="application/merge-patch+json")
            patched.append(name)
    receipt = {
        "plan_id": data.get("plan_id", ""),
        "generation": data.get("generation", ""),
        "job_name": JOB_NAME,
        "observed_at_epoch": now,
        "decision": decision,
        "patched_names": patched,
    }
    request(cm_prefix + quote(RECEIPT_NAME, safe=""), method="PATCH",
            body={"data": {"result": json.dumps(receipt, sort_keys=True)}},
            content_type="application/merge-patch+json")
    print("dispatch=complete")


if __name__ == "__main__":
    main()
