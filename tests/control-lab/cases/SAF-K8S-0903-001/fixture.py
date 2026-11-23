"""Inert inference and explanation HTTP handlers for the scoped lab fixture."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from threading import Thread
from urllib.request import Request, urlopen

MARKER = "FIXTURE:REJECT-0903"
EXPLANATION = {"fixture_id": "SAF-K8S-0903-001-benign-v1",
               "features": [{"name": "signal_a", "value": 0.25},
                            {"name": "signal_b", "value": 0.75}]}
COUNTERS = {"rejections": 0, "explanation_calls": 0,
            "rejection_records": []}


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def reply(self, status, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ready": True})
        self.reply(404, {"reason": "not_found"})

    def read_request(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if 0 < size <= 1024:
                value = json.loads(self.rfile.read(size))
                if isinstance(value, dict):
                    return value
        except (UnicodeError, ValueError):
            pass
        self.reply(400, {"reason": "invalid_fixture_request"})
        return None


class InferenceHandler(FixtureHandler):
    def do_POST(self):
        if self.path == "/admin/counters":
            return self.reply(200, COUNTERS)
        if self.path != "/infer":
            return self.reply(404, {"reason": "not_found"})
        request = self.read_request()
        if request is None:
            return
        if os.environ.get("REJECT_MARKER") == "true" and request.get("fixture_marker") == MARKER:
            COUNTERS["rejections"] += 1
            record = {"rejection_id": "reject-0903-0001", "reason": "fixture_marker_rejected"}
            COUNTERS["rejection_records"] = [record]
            return self.reply(422, record)
        request = Request(os.environ["BACKEND_URL"] + "/model",
                          data=json.dumps({"input": request.get("text")}).encode(),
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=2) as response:
            return self.reply(response.status, json.load(response))


class ExplanationHandler(FixtureHandler):
    def do_POST(self):
        if self.path != "/explain":
            return self.reply(404, {"reason": "not_found"})
        request = self.read_request()
        if request is None:
            return
        if request != {"request_id": "bounded-fixture-v1"}:
            return self.reply(400, {"reason": "bounded_request_required"})
        COUNTERS["explanation_calls"] += 1
        self.reply(200, EXPLANATION)


class ModelHandler(FixtureHandler):
    calls = 0

    def do_GET(self):
        if self.path == "/count":
            return self.reply(200, {"backend_calls": type(self).calls})
        return super().do_GET()

    def do_POST(self):
        if self.path != "/model":
            return self.reply(404, {"reason": "not_found"})
        request = self.read_request()
        if request is None:
            return
        if request != {"input": "ordinary benign fixture"}:
            return self.reply(400, {"reason": "unknown_fixture_input"})
        type(self).calls += 1
        self.reply(200, {"prediction": "fixture-class", "backend_call": type(self).calls})


if __name__ == "__main__":
    if sys.argv[1:] == ["backend"]:
        with ThreadingHTTPServer(("0.0.0.0", 8082), ModelHandler) as backend:
            backend.serve_forever()
    else:
        with ThreadingHTTPServer(("0.0.0.0", 8080), InferenceHandler) as inference:
            with ThreadingHTTPServer(("0.0.0.0", 8081), ExplanationHandler) as explanation:
                Thread(target=explanation.serve_forever, daemon=True).start()
                inference.serve_forever()
