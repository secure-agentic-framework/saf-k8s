"""Serve inert advisory fixtures inside the disposable test cluster."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        mode = Path("/state/mode").read_text().strip()
        if mode != "healthy" and self.path in ("/kubernetes/index.json", "/health"):
            self.send_error(503, "synthetic fixture source outage")
            return
        if self.path == "/kubernetes/index.json":
            body = Path("/fixtures/kubernetes.json").read_bytes()
            content_type = "application/feed+json"
        elif self.path == "/aws/rss.xml":
            body = Path("/fixtures/aws.xml").read_bytes()
            content_type = "application/rss+xml"
        elif self.path == "/health":
            body = json.dumps({"mode": mode}).encode()
            content_type = "application/json"
        else:
            self.send_error(404, "unknown fixture path")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
