"""Minimal HTTPS AdmissionReview endpoint for SAF-K8S-0605-008."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
import signal
import ssl
from pathlib import Path
from urllib.parse import urlsplit


BACKEND = os.environ["SAF_BACKEND"]
CERTIFICATE_SHA256 = hashlib.sha256(Path("/tls/tls.crt").read_bytes()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = "saf-0605-008"

    def log_message(self, *_args):
        # Evidence includes only the case-owned probe name and public fingerprint.
        return

    def do_POST(self):
        if urlsplit(self.path).path != "/validate":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid request length")
            review = json.loads(self.rfile.read(length))
            request = review["request"]
            uid = request["uid"]
            probe = request["name"]
            if (request.get("dryRun") is not True
                    or not probe.startswith("saf-0605-008-")
                    or request.get("resource", {}).get("resource") != "configmaps"
                    or request.get("namespace") != "saf-test"):
                raise ValueError("request outside fixture scope")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        # Fixed, non-sensitive evidence identifies which owned endpoint served it.
        print(json.dumps({"event": "admission", "backend": BACKEND, "probe": probe,
                          "certificate_sha256": CERTIFICATE_SHA256}), flush=True)
        body = json.dumps({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": True},
        }, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)


def terminate(_signum, _frame):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, terminate)
with server:
    server.serve_forever()
