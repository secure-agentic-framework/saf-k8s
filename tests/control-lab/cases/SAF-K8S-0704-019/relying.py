"""Owned TLS relying service that verifies a projected workload token and reads one marker."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request


NS = "saf-test"
AUDIENCE = "saf-fixture-external"
IDENTITY = Path("/var/run/secrets/kubernetes.io/serviceaccount")
PORT = 8443


def api_request(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        "https://kubernetes.default.svc" + path, data,
        {"Authorization": "Bearer " + (IDENTITY / "token").read_text().strip(),
         "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=str(IDENTITY / "ca.crt"))
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return json.load(response)


class Handler(BaseHTTPRequestHandler):
    server_version = "fixture-workload-relying/1"

    def log_message(self, *_args):
        return

    def respond(self, status, body):
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def note(self, alias, decision):
        # Deliberately omit bearer values, request body, and raw principal data.
        print(json.dumps({"event": "identity-read", "workload": alias,
                          "decision": decision}, separators=(",", ":")), flush=True)

    def do_GET(self):
        if self.path == "/ready":
            self.respond(200, {"ready": True})
        else:
            self.respond(404, {"decision": "not-found", "marker": None})

    def do_POST(self):
        if self.path != "/read":
            self.respond(404, {"decision": "not-found", "marker": None})
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4096:
            self.respond(400, {"decision": "invalid-request", "marker": None})
            return
        try:
            request = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeDecodeError):
            self.respond(400, {"decision": "invalid-request", "marker": None})
            return
        if not isinstance(request, dict):
            self.respond(400, {"decision": "invalid-request", "marker": None})
            return
        authorization = self.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme != "Bearer" or not token:
            self.note(self.server.alias, "unauthenticated")
            self.respond(401, {"decision": "unauthenticated", "marker": None})
            return
        try:
            review = api_request("/apis/authentication.k8s.io/v1/tokenreviews", {
                "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                "spec": {"token": token, "audiences": [AUDIENCE]}})["status"]
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            self.note(self.server.alias, "review-unavailable")
            self.respond(503, {"decision": "unavailable", "marker": None})
            return
        if (review.get("authenticated") is not True
                or AUDIENCE not in review.get("audiences", [])):
            self.note(self.server.alias, "unauthenticated")
            self.respond(401, {"decision": "unauthenticated", "marker": None})
            return
        username = review.get("user", {}).get("username")
        if username != self.server.expected_user or request.get("marker") != self.server.marker:
            self.note(self.server.alias, "denied")
            self.respond(403, {"decision": "denied", "marker": None})
            return
        try:
            stored = api_request(f"/api/v1/namespaces/{NS}/configmaps/{self.server.marker}")
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            self.note(self.server.alias, "backend-unavailable")
            self.respond(503, {"decision": "unavailable", "marker": None})
            return
        if stored.get("data", {}).get("marker") != self.server.marker:
            self.note(self.server.alias, "backend-invalid")
            self.respond(503, {"decision": "unavailable", "marker": None})
            return
        self.note(self.server.alias, "allowed")
        self.respond(200, {"decision": "allowed", "principal": self.server.alias,
                           "marker": stored["data"]["marker"]})


def serve(expected_user, marker, alias):
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.expected_user = expected_user
    server.marker = marker
    server.alias = alias
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"event": "relying-ready", "workload": alias}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "serve":
        raise SystemExit("invalid fixture service invocation")
    serve(sys.argv[2], sys.argv[3], sys.argv[4])
