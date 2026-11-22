"""Synthetic destination which checks stage headers before writing marker bytes."""
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, {"status": "ok"})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/receive":
            self.reply(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            marker = Path("/fixture/marker.txt").read_bytes()
            event, stage = {
                "public": ("fixture-transfer-001", "serving-public"),
                "restricted": ("fixture-transfer-ordinary", "validation-restricted"),
            }[sys.argv[1]]
            expected = {
                "X-SAF-Event-ID": event,
                "X-SAF-Source-Stage": "training-restricted",
                "X-SAF-Source-Class": "restricted",
                "X-SAF-Destination-Stage": stage,
                "X-SAF-Destination-Class": sys.argv[1],
                "X-SAF-Marker-SHA256": hashlib.sha256(marker).hexdigest(),
            }
            if length != len(marker) or length > 256 or self.rfile.read(length) != marker:
                self.reply(400, {"error": "marker_mismatch"})
                return
            if any(self.headers.get(name) != allowed for name, allowed in expected.items()):
                self.reply(403, {"error": "destination_scope_mismatch"})
                return
            (Path("/data") / "receipt").write_bytes(marker)
            self.reply(200, {"accepted": True, "sha256": hashlib.sha256(marker).hexdigest()})
        except (OSError, ValueError):
            self.reply(400, {"error": "invalid_request"})


HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
