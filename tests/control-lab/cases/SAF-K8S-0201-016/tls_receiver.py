"""Authenticate the bounded fixture sender and commit the receipt before acknowledgement."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
import ssl
from urllib.parse import parse_qs, urlparse
from pathlib import Path

DATA = Path("/data")
DATABASE = DATA / "native-events.sqlite3"
EXPECTED_CLIENT = "audit-forwarder"


def database():
    connection = sqlite3.connect(DATABASE, timeout=5)
    connection.execute("PRAGMA synchronous = FULL")
    return connection


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def response(self, status, body):
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def principal(self):
        subject = dict(pair for rdn in self.connection.getpeercert()["subject"] for pair in rdn)
        return subject.get("commonName")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/events":
            self.response(404, {"error": "unknown endpoint"})
            return
        if self.principal() != EXPECTED_CLIENT:
            self.response(403, {"error": "client not in fixture policy"})
            return
        serial = parse_qs(parsed.query).get("serial", [None])[0]
        with database() as connection:
            cursor = connection.execute("SELECT body FROM events WHERE serial = ?", (serial,))
            rows = [json.loads(row[0]) for row in cursor]
        self.response(200, rows)

    def do_POST(self):
        principal = self.principal()
        if principal != EXPECTED_CLIENT:
            self.response(403, {"error": "client not in fixture policy"})
            return
        if self.path != "/events":
            self.response(404, {"error": "unknown endpoint"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 4096:
                raise ValueError("invalid fixture event size")
            item = json.loads(self.rfile.read(size))
            if (set(item) != {"source", "serial", "kind", "operation", "success"}
                    or not isinstance(item["serial"], str) or not item["serial"].isdigit()
                    or not isinstance(item["source"], str) or not item["source"].isalnum()
                    or (item["kind"], item["operation"], item["success"]) != ("config", "read", True)):
                raise ValueError("unexpected fixture event")
        except (ValueError, TypeError, KeyError):
            self.response(400, {"error": "unexpected fixture event"})
            return
        if not (DATA / "accepting").exists():
            self.response(503, {"error": "bounded receiver outage"})
            return

        body = json.dumps({**item, "authenticated_source": principal}, sort_keys=True)
        identity = f"{principal}/{item['source']}/{item['serial']}"
        with database() as connection:
            connection.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?)", (identity, item["serial"], body))
            durable, = connection.execute("SELECT body FROM events WHERE identity = ?", (identity,)).fetchone()
        if durable != body:
            self.response(409, {"error": "same fixture identity has different content"})
            return
        self.response(202, {"accepted": True})


with database() as connection:
    connection.execute("CREATE TABLE IF NOT EXISTS events (identity TEXT PRIMARY KEY, serial TEXT, body TEXT)")
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.minimum_version = ssl.TLSVersion.TLSv1_2
tls.load_cert_chain("/tls/server.crt", "/tls/server.key")
tls.load_verify_locations(cafile="/tls/ca.crt")
tls.verify_mode = ssl.CERT_REQUIRED
server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
