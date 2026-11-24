"""Owned telemetry receiver with an explicit one-request outage."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/state":
            self.reply(200, {"http_rejections": self.server.rejections, "receipts": self.server.receipts})
        else:
            self.reply(404, {})

    def do_POST(self):
        if self.path != "/events":
            self.reply(404, {})
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 20000:
            self.reply(400, {})
            return
        row = json.loads(self.rfile.read(size))
        if not self.server.rejections:
            self.server.rejections += 1
            self.reply(503, {})
            return
        key = row["pod_uid"]
        if key in self.server.receipts and self.server.receipts[key] != row:
            self.reply(409, {})
            return
        self.server.receipts[key] = row
        self.reply(201, {"accepted": len(row["events"]), "pod_uid": key})


with HTTPServer(("0.0.0.0", 18082), Receiver) as server:
    server.rejections = 0
    server.receipts = {}
    server.serve_forever()
