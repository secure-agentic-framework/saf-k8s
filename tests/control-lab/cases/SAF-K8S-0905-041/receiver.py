"""Bounded case-local HTTPS receiver with fixture-only Basic authentication."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import binascii
import hmac
import json
import os
from pathlib import Path
import ssl

STORE = Path("/state/alerts.json")
FIELDS = {"alert_id", "event_id", "rule", "actor", "repository"}
EXPECTED_USER = Path("/receiver-auth/username").read_text().strip().encode()
EXPECTED_PASSWORD = Path("/receiver-auth/password").read_text().strip().encode()


def read_state():
    if STORE.exists():
        return json.loads(STORE.read_text())
    return {"alerts": {}, "duplicates": 0}


def save_state(state):
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    tmp.replace(STORE)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        return

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="fixture-alert-receiver"')
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
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
        if self.path == "/health":
            return self.reply(200, {"ready": True})
        if self.path != "/alerts":
            return self.reply(404, {"error": "unknown-route"})
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        state = read_state()
        self.reply(200, {"alerts": [state["alerts"][key] for key in sorted(state["alerts"])],
                         "duplicates": state["duplicates"]})

    def do_POST(self):
        if self.path != "/alerts":
            return self.reply(404, {"error": "unknown-route"})
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                return self.reply(413, {"error": "body-size"})
            value = json.loads(self.rfile.read(size))
        except (TypeError, ValueError):
            return self.reply(400, {"error": "malformed-alert"})
        if (not isinstance(value, dict) or set(value) != FIELDS
                or not all(isinstance(value[key], str) and value[key] for key in FIELDS)):
            return self.reply(422, {"error": "invalid-alert-shape"})
        state = read_state()
        prior = state["alerts"].get(value["alert_id"])
        if prior is not None:
            if prior != value:
                return self.reply(409, {"error": "alert-id-conflict"})
            state["duplicates"] += 1
            save_state(state)
            return self.reply(200, {"accepted": True, "duplicate": True})
        state["alerts"][value["alert_id"]] = value
        save_state(state)
        self.reply(201, {"accepted": True, "duplicate": False})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/receiver-tls/tls.crt", "/receiver-tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
