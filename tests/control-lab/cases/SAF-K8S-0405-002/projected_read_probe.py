"""Make two HTTPS fixture reads with the Pod's projected ServiceAccount."""
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import ssl

NAMESPACE = "saf-test"
IDENTITY_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def get_status(name, host, port, context, token):
    conn = HTTPSConnection(host, port, timeout=10, context=context)
    try:
        conn.request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}",
                     headers={"Authorization": "Bearer " + token})
        return conn.getresponse().status
    finally:
        conn.close()


def main():
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = int(os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])
    context = ssl.create_default_context(cafile=IDENTITY_DIR / "ca.crt")
    token = (IDENTITY_DIR / "token").read_text(encoding="utf-8").strip()
    result = {
        "allowed": get_status("fixture-identity-allowed", host, port, context, token),
        "denied": get_status("fixture-identity-denied", host, port, context, token),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
