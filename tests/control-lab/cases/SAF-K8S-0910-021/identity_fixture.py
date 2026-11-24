"""Verify actual client URI identities on a fixture mTLS gateway."""
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import sys
import threading

ALLOWED = "spiffe://saf.test/ns/saf-test/sa/fixture-signed-caller"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        cert = self.connection.getpeercert()
        identities = [value for scheme, value in cert.get("subjectAltName", ()) if scheme == "URI"]
        who = identities[0] if len(identities) == 1 else None
        accepted = not self.server.restricted or who == ALLOWED
        code = 200 if accepted else 403
        reply = {"caller": who, "decision": "allowed" if accepted else "refused",
                 "response": "synthetic-identity-ack" if accepted else None}
        payload = json.dumps(reply, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        print(json.dumps({"mode": "verified-identity" if self.server.restricted else "trusted-chain",
                          "status": code, **reply}, sort_keys=True), flush=True)
        self.wfile.write(payload)


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    context.load_verify_locations("/trust/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    servers = []
    for port, scoped in ((8443, False), (8444, True)):
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        server.restricted = scoped
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
    threading.Thread(target=servers[0].serve_forever, daemon=True).start()
    servers[1].serve_forever()


def probe(host, port, expected):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    chain = Path("/credential/tls.crt")
    if chain.is_file():
        context.load_cert_chain(str(chain), "/credential/tls.key")
    try:
        with socket.create_connection((host, port), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=expected) as tls:
                tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
                response = HTTPResponse(tls)
                response.begin()
                return {"status": response.status, "body": json.load(response)}
    except ssl.SSLCertVerificationError as error:
        if error.verify_code == 62:  # OpenSSL X509_V_ERR_HOSTNAME_MISMATCH
            return {"status": "destination-identity-refused"}
        return {"status": "certificate-verification-failed", "verify_code": error.verify_code}
    except ssl.SSLError as error:
        if error.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED":
            return {"status": "client-tls-refused"}
        return {"status": "tls-unavailable", "reason": error.reason}
    except (OSError, EOFError):
        return {"status": "transport-unavailable"}


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        print(json.dumps(probe(sys.argv[1], int(sys.argv[2]), sys.argv[3]), sort_keys=True))
