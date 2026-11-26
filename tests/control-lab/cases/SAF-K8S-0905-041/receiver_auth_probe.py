"""Prove wrong fixture credentials cannot add an alert over verified TLS."""
import base64
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

user = Path("/receiver-wrong-auth/username").read_text().strip()
password = Path("/receiver-wrong-auth/password").read_text().strip()
identity = base64.b64encode(f"{user}:{password}".encode()).decode()
alert = {"alert_id": "auth-probe-denied", "event_id": "auth-probe-denied",
         "rule": "sensitive-publish", "actor": "fixture-publisher",
         "repository": "saf-test/model-a"}
request = Request(sys.argv[1] + "/alerts",
                  data=json.dumps(alert, sort_keys=True, separators=(",", ":")).encode(),
                  headers={"Content-Type": "application/json", "Authorization": "Basic " + identity},
                  method="POST")
context = ssl.create_default_context(cafile="/receiver-ca/ca.pem")
try:
    with urlopen(request, context=context, timeout=5) as response:
        status = response.status
except HTTPError as error:
    status = error.code
print(json.dumps({"wrong_credential_rejected": status == 401, "status": status}, sort_keys=True))
