"""Send one in-memory projected token to the pinned local TLS relying service."""
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request


host, token_path, marker = sys.argv[1:4]
token = (Path("/identity") / token_path).read_text().strip()
request = urllib.request.Request(
    f"https://{host}:8443/read", data=json.dumps({"marker": marker}).encode(),
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    method="POST")
context = ssl.create_default_context(cafile="/identity/ca.crt")
try:
    with urllib.request.urlopen(request, context=context, timeout=8) as response:
        status, body = response.status, json.load(response)
except urllib.error.HTTPError as error:
    status = error.code
    try:
        body = json.loads(error.read())
    except (ValueError, OSError):
        body = {}
print(json.dumps({"http_status": status, "decision": body.get("decision"),
                  "principal": body.get("principal"), "marker": body.get("marker"),
                  "reason": body.get("reason"),
                  "authenticated": body.get("authenticated"),
                  "audience_valid": body.get("audience_valid"),
                  "subject_valid": body.get("subject_valid"),
                  "pod_binding_matches": body.get("pod_binding_matches"),
                  "token_pod_name": body.get("token_pod_name"),
                  "token_pod_uid": body.get("token_pod_uid")},
                 sort_keys=True), flush=True)
