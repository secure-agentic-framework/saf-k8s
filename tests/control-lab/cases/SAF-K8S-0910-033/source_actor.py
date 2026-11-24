"""Emit one bounded source receipt using the Pod's own scoped API identity."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import re
import ssl
import sys

TRACE = "synthetic-telemetry-investigation-004"
MARKER = "fixture-investigation-004"
CREDENTIALS = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def record(body_sha256):
    if re.fullmatch(r"[a-f0-9]{64}", body_sha256) is None:
        raise ValueError("The fixture digest is invalid")
    context = ssl.create_default_context(cafile=str(CREDENTIALS / "ca.crt"))
    connection = HTTPSConnection("kubernetes.default.svc", context=context, timeout=5)
    receipt = {"trace": TRACE, "body_sha256": body_sha256, "classification": "authorized-fixture"}
    try:
        connection.request("PATCH", f"/api/v1/namespaces/saf-test/configmaps/{MARKER}", body=json.dumps({
            "data": receipt,
        }), headers={
            "Authorization": "Bearer " + (CREDENTIALS / "token").read_text().strip(),
            "Content-Type": "application/merge-patch+json",
        })
        response = connection.getresponse()
        result = json.loads(response.read(65536))
    finally:
        connection.close()
    if response.status != 200 or result.get("data") != receipt:
        raise RuntimeError("The source API did not persist the exact fixture receipt")
    return {"name": result["metadata"]["name"], "status": response.status, "record": receipt}


if __name__ == "__main__":
    print(json.dumps(record(sys.argv[1]), sort_keys=True))
