"""Submit only fixed, synthetic ConfigMap patches using this Pod's own identity."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys

MOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
BASE = "/api/v1/namespaces/saf-test/configmaps/"
PURGE_LEDGER = BASE + "saf-audit-purge-ledger"
PURGE = BASE + "synthetic-audit-purge-record"
LEDGER = BASE + "saf-audit-approval-ledger"
TARGET = BASE + "synthetic-audit-log-record"
DECOY = BASE + "synthetic-audit-log-decoy"
action = sys.argv[1]
dry = action.startswith("dry-")
operation = action[4:] if dry else action
if operation.endswith("-vote"):
    ballot, field = (PURGE_LEDGER, operation[6:-5]) if operation.startswith("purge-") else (LEDGER, operation[:-5])
    if field not in {"security", "records"}:
        raise SystemExit("invalid fixture reviewer vote")
    method, path = "PATCH", ballot
    body = {"data": {field: "approved"}}
elif operation in {"target-update", "decoy-update", "direct-target-update", "event-update"}:
    method = "PATCH"
    path = DECOY if operation == "decoy-update" else TARGET
    if operation == "event-update":
        body = {"data": {"event": "synthetic event: changed by out-of-scope action"}}
    else:
        body = {"data": {"annotation": "reviewed"}}
elif operation in {"purge", "purge-decoy"}:
    method = "DELETE"
    path = DECOY if operation == "purge-decoy" else PURGE
    body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": sys.argv[2]}}
else:
    raise SystemExit("invalid fixture action")
if dry:
    if method == "DELETE":
        body["dryRun"] = ["All"]
    else:
        path += "?dryRun=All"
ca = ssl.create_default_context(cafile=str(MOUNT / "ca.crt"))
connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=ca)
headers = {"Authorization": "Bearer " + (MOUNT / "token").read_text().strip(),
           "Content-Type": "application/json" if method == "DELETE" else "application/merge-patch+json"}
try:
    connection.request(method, path, body=json.dumps(body), headers=headers)
    response = connection.getresponse()
    data = json.load(response)
    print(json.dumps({"code": response.status, "reason": data.get("reason"),
                      "detail": data.get("message") or ""}))
finally:
    connection.close()
