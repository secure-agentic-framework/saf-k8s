"""Independent recipient of the owned Falco JSON alert."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Recipient(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_json(200, self.server.alerts)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/alerts" or not 0 < size < 20000:
            self.send_json(400, {})
            return
        self.server.alerts.append(json.loads(self.rfile.read(size)))
        self.send_json(200, {"accepted": len(self.server.alerts)})


with HTTPServer(("0.0.0.0", 18082), Recipient) as server:
    server.alerts = []
    server.serve_forever()
