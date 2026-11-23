"""Case-owned marker backend. Record only the fixed fixture marker."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_json({"healthy": True} if self.path == "/health" else {}, 200 if self.path == "/health" else 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length))
        marker = request.get("marker")
        print(json.dumps({"arrival": marker}), flush=True)
        self.send_json({"arrived": marker}, 200)

    def send_json(self, document, status):
        payload = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Backend).serve_forever()
