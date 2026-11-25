"""Case-local Alertmanager webhook sink. No forwarding, disk writes, or logging."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock

MAX_BODY = 32768
messages = []
lock = Lock()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/state":
            self.reply(404, {"error": "not_found"})
            return
        with lock:
            self.reply(200, {"message_count": len(messages), "messages": list(messages)})

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/events" or not 0 < size <= MAX_BODY:
            self.reply(400, {"error": "invalid_request"})
            return
        try:
            payload = json.loads(self.rfile.read(size))
            if (payload.get("receiver") != "case-local-inert"
                    or not isinstance(payload.get("alerts"), list)
                    or len(payload["alerts"]) != 1):
                raise ValueError("unexpected_webhook_envelope")
        except (ValueError, AttributeError, TypeError):
            self.reply(400, {"error": "invalid_webhook"})
            return
        with lock:
            messages.append(payload)
        self.reply(200, {"accepted": True})

    def log_message(self, *_args):
        return


ThreadingHTTPServer(("0.0.0.0", 18082), Handler).serve_forever()
