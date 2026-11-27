"""Case-owned TLS receiver; authenticate without logging request metadata."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import binascii
import hmac
import hashlib
import json
import os
from pathlib import Path
import ssl

STORE = Path("/sink/events.jsonl")
EXPECTED_USER = Path("/sink-auth/username").read_text().strip().encode()
EXPECTED_PASSWORD = Path("/sink-auth/password").read_text().strip().encode()
RETRY_PATH = "/v2/saf-test/audit-model/manifests/retry-503-v1"
RETRY_STATE = {
    "rejected_attempts": 0,
    "accepted_attempts": 0,
    "rejected_body_sha256": [],
    "accepted_body_sha256": [],
    "rejected_marker_records": 0,
    "accepted_marker_records": 0,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _reply(self, status, payload=b""):
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="fixture-sink"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:], validate=True)
            user, password = raw.split(b":", 1)
        except (ValueError, binascii.Error):
            return False
        return hmac.compare_digest(user, EXPECTED_USER) and hmac.compare_digest(password, EXPECTED_PASSWORD)

    def do_GET(self):
        if self.path not in {"/events", "/retry-state"}:
            self._reply(404)
            return
        if not self._authorized():
            self._reply(401)
            return
        if self.path == "/retry-state":
            self._reply(200, json.dumps(RETRY_STATE, sort_keys=True).encode())
            return
        payload = STORE.read_bytes() if STORE.exists() else b""
        self._reply(200, payload)

    def do_POST(self):
        if self.path not in {"/audit", "/access"}:
            self._reply(404)
            return
        if not self._authorized():
            self._reply(401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 1048576:
            self._reply(413)
            return
        try:
            body = self.rfile.read(length)
            events = [json.loads(line) for line in body.splitlines()]
            if not events or not all(isinstance(event, dict) for event in events):
                raise ValueError("expected event records")
        except (UnicodeDecodeError, ValueError):
            self._reply(400)
            return
        marker = [event for event in events if self.path == "/access"
                  and event.get("message") == "HTTP API"
                  and event.get("method") == "PUT"
                  and event.get("path") == RETRY_PATH
                  and event.get("statusCode") == 201
                  and event.get("username") == "fixture-publisher"]
        body_digest = hashlib.sha256(body).hexdigest()
        if marker and RETRY_STATE["rejected_attempts"] == 0:
            RETRY_STATE["rejected_attempts"] += 1
            RETRY_STATE["rejected_marker_records"] = len(marker)
            RETRY_STATE["rejected_body_sha256"].append(body_digest)
            self._reply(503)
            return
        if marker:
            RETRY_STATE["accepted_attempts"] += 1
            RETRY_STATE["accepted_marker_records"] += len(marker)
            RETRY_STATE["accepted_body_sha256"].append(body_digest)
        with STORE.open("a", encoding="utf-8") as output:
            for event in events:
                output.write(json.dumps({"stream": self.path[1:], "event": event}) + "\n")
            output.flush()
            os.fsync(output.fileno())
        self._reply(201)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
