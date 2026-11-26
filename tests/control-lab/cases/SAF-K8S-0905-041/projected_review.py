"""Use the Pod's projected Kubernetes identity for one named review record."""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ACTION, NAME, ALERT_ID = sys.argv[1:4]
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
HOST = os.environ["KUBERNETES_SERVICE_HOST"]
PORT = os.environ["KUBERNETES_SERVICE_PORT"]
URL = f"https://{HOST}:{PORT}/api/v1/namespaces/saf-test/configmaps/{NAME}"
TOKEN = TOKEN_PATH.read_text().strip()
CONTEXT = ssl.create_default_context(cafile=CA_PATH)


def request(method, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + TOKEN}
    if data is not None:
        headers["Content-Type"] = "application/merge-patch+json"
    req = urllib.request.Request(URL, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=CONTEXT, timeout=8) as response:
            return response.status, json.loads(response.read()) if method == "GET" else None
    except urllib.error.HTTPError as exc:
        return exc.code, None


if ACTION == "deny":
    denied, _ = request("PATCH", {"data": {"disposition": "reviewed-fixture-event"}})
    read_status, current = request("GET")
    data = current.get("data", {}) if current else {}
    print(json.dumps({
        "patch_forbidden": denied == 403,
        "read_ok": read_status == 200,
        "unchanged": data == {"alert_id": ALERT_ID, "event_id": ALERT_ID.removeprefix("alert-"),
                              "disposition": "unreviewed"},
        "alert_id_matches": data.get("alert_id") == ALERT_ID,
    }, sort_keys=True))
elif ACTION == "approve":
    status, _ = request("PATCH", {"data": {"disposition": "reviewed-fixture-event"}})
    print(json.dumps({"patch_accepted": status == 200}, sort_keys=True))
elif ACTION == "readback":
    status, current = request("GET")
    data = current.get("data", {}) if current else {}
    print(json.dumps({
        "read_ok": status == 200,
        "exact_alert_id": data.get("alert_id") == ALERT_ID,
        "exact_event_id": data.get("event_id") == ALERT_ID.removeprefix("alert-"),
        "reviewed": data.get("disposition") == "reviewed-fixture-event",
    }, sort_keys=True))
else:
    raise SystemExit("unknown action")
