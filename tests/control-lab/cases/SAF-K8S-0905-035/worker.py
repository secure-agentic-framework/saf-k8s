"""Serve bounded inert responses for three model health conditions."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import time


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            status, body = 200, b"ready"
        elif self.path == "/infer":
            mode = os.environ["MODE"]
            if mode == "slow":
                time.sleep(0.45)
            status, body = (503 if mode == "error" else 200), os.environ["VERSION"].encode()
        else:
            status, body = 404, b"unknown"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
