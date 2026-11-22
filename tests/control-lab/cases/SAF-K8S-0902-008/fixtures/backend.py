"""Two fixed-response model backend mocks; request metadata only is logged."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODEL = os.environ["FIXTURE_MODEL"]
MARKER = os.environ["FIXTURE_MARKER"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        event_id = self.headers.get("X-Fixture-Event-ID", "invalid")
        if self.path != "/infer" or event_id not in {
                "red-absent", "red-wrong-model", "green-absent",
                "green-wrong-model", "positive-alpha", "positive-beta"}:
            self.send_error(404)
            return
        print(json.dumps({"event_id": event_id, "model": MODEL,
                          "result": "served-fixed-marker"}, sort_keys=True), flush=True)
        body = json.dumps({"model": MODEL, "result": MARKER}, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        body = json.dumps({"result": "not-found"}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
