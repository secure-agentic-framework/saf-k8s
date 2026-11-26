"""Perform one fixture-only public-key registration with each scoped identity."""
import base64
from http.client import HTTPConnection
import json
from pathlib import Path

PUBLISHER = "fixture-publisher"
ADMIN = "fixture-registry-admin"
PATH = "/v2/_zot/ext/cosign"


def post(username, password_file, body):
    password = Path(password_file).read_text(encoding="utf-8").strip()
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    connection = HTTPConnection("with-forwarding", 5000, timeout=8)
    try:
        connection.request("POST", PATH, body=body,
                           headers={"Authorization": "Basic " + encoded,
                                    "Content-Type": "text/plain"})
        return connection.getresponse().status
    finally:
        connection.close()


def main():
    body = Path("/cosign/public.pem").read_bytes()
    denied = post(PUBLISHER, "/auth/password", body)
    allowed = post(ADMIN, "/auth/admin-password", body)
    print(json.dumps({"non_admin_status": denied, "admin_status": allowed,
                      "non_admin_denied": denied == 403, "admin_allowed": allowed == 200},
                     sort_keys=True))


if __name__ == "__main__":
    main()
