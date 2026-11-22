"""Serve readiness only for a synthetic marker mounted from a case fixture."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path


marker = Path("/fixture/component-marker.txt").read_bytes()
marker_digest = sha256(marker).hexdigest()
component = os.environ["COMPONENT_ID"]
release = os.environ["RELEASE_ID"]
print(json.dumps({"component_id": component, "release_id": release,
                  "marker_sha256": marker_digest}, sort_keys=True), flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/ready":
            self.send_error(404)
            return
        body = json.dumps({"ready": True, "component_id": component,
                           "release_id": release, "marker_sha256": marker_digest},
                          sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
