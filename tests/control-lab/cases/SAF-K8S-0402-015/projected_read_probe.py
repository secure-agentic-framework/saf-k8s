"""Perform one bounded HTTPS read with an explicitly projected fixture token."""
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import ssl


def main():
    identity = Path("/var/run/saf-projected")
    token = (identity / "token").read_text(encoding="utf-8").strip()
    context = ssl.create_default_context(cafile=identity / "ca.crt")
    connection = HTTPSConnection(
        os.environ["KUBERNETES_SERVICE_HOST"],
        int(os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]),
        timeout=10,
        context=context,
    )
    try:
        connection.request(
            "GET",
            "/api/v1/namespaces/" + os.environ["SAF_NAMESPACE"]
            + "/configmaps/" + os.environ["SAF_TARGET"],
            headers={"Authorization": "Bearer " + token},
        )
        response = connection.getresponse()
        status = response.status
        response.read()  # consume, never print or persist the marker response
    finally:
        connection.close()
    del token
    print(json.dumps({"body_retained": False, "https_status": status}, sort_keys=True))


if __name__ == "__main__":
    main()
