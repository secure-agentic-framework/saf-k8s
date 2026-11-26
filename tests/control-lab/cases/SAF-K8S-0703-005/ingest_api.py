"""One-record, emptyDir-backed HTTP ingest fixture. Never logs request bytes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

MAX_BODY_BYTES = 4
RECORD_PATH = Path("/data/record")
RECORD_PATH.write_bytes(b"INIT")
revision = 0


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global revision
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/records/fixture-one":
            self.send_json(200, {"id": "fixture-one", "revision": revision,
                                 "record_hex": RECORD_PATH.read_bytes().hex()})
        else:
            self.send_json(404, {"error": "not-found"})

    def do_POST(self):
        global revision
        if self.path != "/records/fixture-one/ingest":
            self.send_json(404, {"error": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            self.send_json(400, {"error": "invalid-length"})
            return
        if length > MAX_BODY_BYTES:
            self.send_json(413, {"error": "input-too-large", "limit_bytes": MAX_BODY_BYTES})
            return
        if length != MAX_BODY_BYTES:
            self.send_json(422, {"error": "input-must-match-fixture-size"})
            return
        value = self.rfile.read(length)
        if len(value) != length:
            self.send_json(400, {"error": "incomplete-body"})
            return
        RECORD_PATH.write_bytes(value)
        revision += 1
        self.send_json(202, {"accepted": True, "revision": revision})

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler's default log includes the request line. Keep
        # fixture request details out of the pod log and evidence.
        return


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
