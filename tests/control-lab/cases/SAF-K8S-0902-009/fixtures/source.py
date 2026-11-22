"""Serve only checked-in fixture bytes on local paths; never log response content."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

FIXTURE = json.loads(Path("/case/response-fixture.json").read_text(encoding="utf-8"))
ROUTES = {
    "/fixture": FIXTURE["response_body"].encode("utf-8"),
    "/intended": FIXTURE["intended_output"].encode("utf-8"),
    "/at-cap": FIXTURE["at_cap_body"].encode("utf-8"),
    "/over-cap": FIXTURE["over_cap_body"].encode("utf-8"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, b"ready")
        elif self.path in ROUTES:
            self._send(200, ROUTES[self.path])
        else:
            self._send(404, b"not found")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
