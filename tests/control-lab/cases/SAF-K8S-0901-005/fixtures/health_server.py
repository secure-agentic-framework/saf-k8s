"""Fixed-marker HTTP health responder for SAF-K8S-0901-005 mock pods."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FIXTURE = os.environ["SAF_FIXTURE_NAME"]
MARKER = os.environ["SAF_HEALTH_MARKER"]


class Handler(BaseHTTPRequestHandler):
    server_version = "saf-0901-005"

    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = (MARKER + "\n").encode("ascii")
        print(json.dumps({"event": "health_served", "fixture": FIXTURE,
                          "path": "/healthz"}, sort_keys=True), flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
