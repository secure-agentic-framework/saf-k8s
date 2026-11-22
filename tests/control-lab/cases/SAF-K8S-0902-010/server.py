"""Inert local role-boundary fixture; it never calls a model or external service."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

MODE = os.environ.get("POLICY_MODE", "")
TRUSTED_SYSTEM = "Fixture system context."
TRUSTED_DEVELOPER = "Fixture developer context."
BACKEND = {"dispatch_count": 0, "last_messages": [], "last_roles": []}


def build_trusted_messages(content):
    return [
        {"role": "system", "content": TRUSTED_SYSTEM},
        {"role": "developer", "content": TRUSTED_DEVELOPER},
        {"role": "user", "content": content},
    ]


def dispatch(messages):
    """Record only local fixture messages and return a fixed harmless answer."""
    BACKEND["dispatch_count"] += 1
    BACKEND["last_messages"] = messages
    BACKEND["last_roles"] = [message["role"] for message in messages]
    return "4"


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ready": True, "mode": MODE})
        elif self.path == "/state":
            self._send(200, {"mode": MODE, **BACKEND})
        else:
            self._send(404, {"reason": "not_found"})

    def do_POST(self):
        if self.path != "/public":
            self._send(404, {"reason": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                self._send(400, {"reason": "invalid_size"})
                return
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"reason": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send(400, {"reason": "invalid_shape"})
            return

        if MODE == "on":
            if "developer" in request or "system" in request:
                self._send(400, {"reason": "reserved_role_field"})
                return
            if set(request) != {"role", "content"}:
                self._send(400, {"reason": "unsupported_field"})
                return
        role = request.get("role")
        content = request.get("content")
        if role != "user":
            self._send(400, {"reason": "unknown_role"})
            return
        if not isinstance(content, str) or not content or len(content) > 256:
            self._send(400, {"reason": "invalid_content"})
            return

        messages = build_trusted_messages(content)
        answer = dispatch(messages)
        self._send(200, {"accepted": True, "answer": answer,
                         "metadata_ignored": "metadata" in request})

    def log_message(self, *_args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
