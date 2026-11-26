"""Case-owned TLS receiver; authenticate without logging request metadata."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import binascii
import hmac
import json
import os
from pathlib import Path
import ssl

STORE = Path("/sink/events.jsonl")
EXPECTED_USER = Path("/sink-auth/username").read_text().strip().encode()
EXPECTED_PASSWORD = Path("/sink-auth/password").read_text().strip().encode()


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
        if self.path != "/events":
            self._reply(404)
            return
        if not self._authorized():
            self._reply(401)
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
            events = [json.loads(line) for line in self.rfile.read(length).splitlines()]
            if not events or not all(isinstance(event, dict) for event in events):
                raise ValueError("expected event records")
        except (UnicodeDecodeError, ValueError):
            self._reply(400)
            return
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
