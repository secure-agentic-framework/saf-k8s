"""Apply an exact caller-to-operation policy after fixture mutual TLS."""
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler
import json
import socket
import ssl
import sys

import identity_fixture

OPERATIONS = {
    "spiffe://saf.test/ns/saf-test/sa/fixture-signed-caller": "/v1/gradient/shard-a",
    "spiffe://saf.test/ns/saf-test/sa/fixture-other-caller": "/v1/gradient/shard-b",
    "spiffe://saf.test/ns/saf-test/sa/fixture-network-unapproved": "/v1/gradient/shard-a",
}
BODY = b'{"synthetic":"gradient-shard"}'


class RouteHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        identities = [value for kind, value in self.connection.getpeercert().get("subjectAltName", ())
                      if kind == "URI"]
        caller = identities[0] if len(identities) == 1 else None
        size = int(self.headers.get("Content-Length", "0"))
        expected = OPERATIONS.get(caller)
        if expected is None or self.path not in OPERATIONS.values() or size != len(BODY):
            self.send_error(400)
            return
        if self.rfile.read(size) != BODY:
            self.send_error(400)
            return
        allowed = not self.server.restricted or self.path == expected
        status = 200 if allowed else 403
        record = {"caller": caller, "operation": self.path,
                  "decision": "accepted" if allowed else "operation-not-authorized"}
        payload = json.dumps(record, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        print(json.dumps({"mode": "scoped" if self.server.restricted else "baseline",
                          "status": status, **record}, sort_keys=True), flush=True)
        self.wfile.write(payload)


def probe(host, port, hostname, operation):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    try:
        raw = socket.create_connection((host, port), timeout=4)
    except (ConnectionRefusedError, TimeoutError):
        return {"status": "route-unavailable"}
    with raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            headers = (f"POST {operation} HTTP/1.0\r\n"
                       f"Content-Type: application/json\r\nContent-Length: {len(BODY)}\r\n\r\n")
            tls.sendall(headers.encode("ascii") + BODY)
            response = HTTPResponse(tls)
            response.begin()
            return {"status": response.status, "body": json.load(response), "tls": tls.version()}


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        identity_fixture.Handler = RouteHandler
        identity_fixture.serve()
    else:
        print(json.dumps(probe(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]), sort_keys=True))
