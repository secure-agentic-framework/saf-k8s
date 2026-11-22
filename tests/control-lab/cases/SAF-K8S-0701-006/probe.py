"""Submit one predetermined API operation with this fixture Pod's own identity."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys

MOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
PV = "/api/v1/persistentvolumes/synthetic-retained-archive"
LEDGER = "/api/v1/namespaces/saf-test/configmaps/saf-approval-ledger"
action = sys.argv[1]
if action in {"delete", "dry-delete"}:
    method, path = "DELETE", PV
    body = {"apiVersion": "v1", "kind": "DeleteOptions"}
    if action == "dry-delete":
        body["dryRun"] = ["All"]
    content_type = "application/json"
elif action in {"security-vote", "data-vote", "check-other-vote"}:
    method, path = "PATCH", LEDGER
    key = "security" if action == "security-vote" else "dataOwner"
    body = {"data": {key: "approved"}}
    if action == "check-other-vote":
        path += "?dryRun=All"
    content_type = "application/merge-patch+json"
else:
    raise SystemExit("invalid fixture action")

ca = ssl.create_default_context(cafile=str(MOUNT / "ca.crt"))
connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=ca)
headers = {"Authorization": "Bearer " + (MOUNT / "token").read_text().strip(),
           "Content-Type": content_type}
try:
    connection.request(method, path, body=json.dumps(body), headers=headers)
    response = connection.getresponse()
    data = json.load(response)
    print(json.dumps({"code": response.status, "reason": data.get("reason"), "detail": data.get("message") or ""}))
finally:
    connection.close()
