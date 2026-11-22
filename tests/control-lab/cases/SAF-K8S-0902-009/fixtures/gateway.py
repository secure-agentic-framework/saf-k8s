"""Bounded local reverse proxy with one exact fixture-marker rule."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))

FIXTURE = json.loads(Path("/case/response-fixture.json").read_text(encoding="utf-8"))
ENABLED = os.environ.get("SAF_FILTER_ENABLED") == "true"
SOURCE = os.environ["SAF_SOURCE_URL"]
CAP = int(os.environ["SAF_OUTPUT_CAP_BYTES"])
if CAP != 96:
    raise ValueError("case output cap must remain exactly 96 bytes")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, b"ready")
            return
        if self.path not in {"/fixture", "/intended", "/at-cap", "/over-cap"}:
            self._send(404, b"not found")
            return
        try:
            with opener.open(SOURCE + self.path, timeout=3) as response:
                status = response.status
                body = response.read(CAP + 2)
        except (URLError, TimeoutError, OSError):
            self._send(502, b"fixture upstream unavailable")
            return
        if len(body) > CAP + 1:
            self._send(413, FIXTURE["cap_denial_body"].encode("utf-8"))
            return
        if ENABLED:
            private = FIXTURE["private_dummy_marker"].encode("utf-8")
            replacement = FIXTURE["redaction_token"].encode("utf-8")
            body = body.replace(private, replacement)
        if ENABLED and len(body) > CAP:
            denial = FIXTURE["cap_denial_body"].encode("utf-8")
            self._send(413, denial)
            return
        self._send(status, body)

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
