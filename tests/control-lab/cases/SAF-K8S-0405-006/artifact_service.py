"""Authorize public test artifact bytes using bounded authenticated attributes."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import sys
from urllib.request import Request, urlopen

AUDIENCE = "saf-artifact-fixture"
API_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
API_CA = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
DATA = Path("/fixture/policy.json")


def identify(token):
    review = {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]},
    }
    req = Request("https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
                  data=json.dumps(review).encode(), headers={
                      "Content-Type": "application/json",
                      "Authorization": "Bearer " + API_TOKEN.read_text().strip(),
                  })
    ca = ssl.create_default_context(cafile=str(API_CA))
    with urlopen(req, context=ca, timeout=5) as response:
        status = json.load(response)["status"]
    if status.get("authenticated") and AUDIENCE in status.get("audiences", []):
        return status["user"]["username"]
    return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self.answer(401, "identity-required")
            return
        try:
            subject = identify(header.removeprefix("Bearer "))
        except (OSError, ValueError, KeyError):
            self.answer(503, "identity-authority-unavailable")
            return
        if subject not in self.server.data["subjects"]:
            self.answer(401, "identity-untrusted")
            return
        artifact = self.server.data["artifacts"].get(self.path.removeprefix("/artifact/"))
        if not artifact:
            self.answer(404, "fixture-artifact-unavailable")
            return
        if self.server.enforce:
            attributes = self.server.data["subjects"][subject]
            for field in ("classification", "sensitivity", "environment"):
                if artifact[field] not in attributes[field]:
                    self.answer(403, field)
                    return
        self.answer(200, "approved", artifact["content"])

    def answer(self, status, decision, marker=None):
        body = json.dumps({"decision": decision, "marker": marker}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def serve(mode):
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    server.data = json.loads(DATA.read_text())
    server.enforce = mode == "enforced"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def probe(host, item):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    client = HTTPSConnection(host, 8443, context=context, timeout=7)
    try:
        token = Path("/identity/token").read_text().strip()
        client.request("GET", "/artifact/" + item, headers={"Authorization": "Bearer " + token})
        response = client.getresponse()
        print(json.dumps({"status": response.status, **json.loads(response.read())}))
    finally:
        client.close()


if sys.argv[1] == "server":
    serve(sys.argv[2])
else:
    probe(*sys.argv[2:])
