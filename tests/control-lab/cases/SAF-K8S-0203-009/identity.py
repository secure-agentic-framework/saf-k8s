"""Test-only identity mapping using the owned Kubernetes TokenReview API."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import sys
import urllib.request

APPROVED = "system:serviceaccount:saf-test:fixture-workload-approved"
ALTERNATE = "system:serviceaccount:saf-test:fixture-workload-other"
AUDIENCE = "saf-fixture-workload"
DIRECTORY = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def review(value):
    trusted = ssl.create_default_context(cafile=str(DIRECTORY / "ca.crt"))
    payload = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
               "spec": {"token": value, "audiences": [AUDIENCE]}}
    own = (DIRECTORY / "token").read_text().strip()
    request = urllib.request.Request("https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
                                     data=json.dumps(payload).encode(),
                                     headers={"Authorization": f"Bearer {own}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, context=trusted, timeout=5) as response:
        return json.load(response)["status"]


class Identity(BaseHTTPRequestHandler):
    def do_GET(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        if self.path != "/v1/identity" or scheme != "Bearer" or not value:
            self.send_error(401)
            return
        status = review(value)
        if status.get("authenticated") is not True or AUDIENCE not in status.get("audiences", []):
            self.send_error(401)
            return
        subject = status.get("user", {}).get("username")
        allowed = {APPROVED, ALTERNATE} if sys.argv[1] == "shared" else {APPROVED}
        if subject not in allowed:
            self.send_error(403)
            return
        payload = json.dumps({"provider_principal": "fixture-workload-role", "public_marker": "authorized fixture"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        pass


server = ThreadingHTTPServer(("0.0.0.0", 8443), Identity)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/server.crt", "/tls/server.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
