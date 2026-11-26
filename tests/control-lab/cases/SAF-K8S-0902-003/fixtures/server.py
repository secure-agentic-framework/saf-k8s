"""Case-owned mock gateway, model, and backend. No external network access."""
import http.client
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


POLICY = json.loads(Path("/fixture/policy.json").read_text(encoding="utf-8"))
LIMIT = POLICY["max_body_bytes"]
MARKER = POLICY["accepted_marker"].encode("ascii")
MODE = os.environ["MODE"]
ENFORCE = os.environ.get("FIXTURE_ENFORCE", "true") == "true"
backend_calls = 0
last_request_id = None


def valid_schema(value):
    """Enforce the exact JSON Schema subset declared in the fixture policy."""
    schema = POLICY["schema"]
    if type(value) is not dict or schema.get("type") != "object":
        return False
    properties = schema.get("properties", {})
    if schema.get("additionalProperties") is False and set(value) - set(properties):
        return False
    if not set(schema.get("required", ())) <= set(value):
        return False
    for name, item in value.items():
        rule = properties.get(name)
        if not isinstance(rule, dict):
            return False
        expected_type = rule.get("type")
        if expected_type == "string" and type(item) is not str:
            return False
        if expected_type == "string" and len(item) < rule.get("minLength", 0):
            return False
    return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        # Request lines and bodies are intentionally excluded from pod logs.
        return

    def reply(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def json_reply(self, status, value):
        self.reply(status, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, b"ok", "text/plain")
        elif MODE == "backend" and self.path == "/state":
            self.json_reply(200, {"accepted_calls": backend_calls,
                                  "last_request_id": last_request_id})
        else:
            self.json_reply(404, {"status": "not_found"})

    def do_POST(self):
        global backend_calls, last_request_id
        if self.path != "/infer":
            self.json_reply(404, {"status": "not_found"})
            return
        if MODE in {"gateway", "model"}:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if ENFORCE and content_type != "application/json":
                self.json_reply(415, {"status": "unsupported_content_type"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0 or length > LIMIT + 1:
                self.json_reply(400, {"status": "invalid_content_length"})
                return
            if ENFORCE and length > LIMIT:
                # Read at most one byte beyond the configured cap, then close.
                self.rfile.read(LIMIT + 1)
                self.reply(413, b'{"status":"body_too_large"}')
                return
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.json_reply(400, {"status": "invalid_json"})
                return
            if ENFORCE and not valid_schema(value):
                self.json_reply(422, {"status": "schema_invalid"})
                return
            if MODE == "gateway":
                connection = http.client.HTTPConnection("127.0.0.1", 9001, timeout=3)
                try:
                    connection.request("POST", "/infer", body=raw,
                                       headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    response_body = response.read()
                except OSError:
                    self.json_reply(502, {"status": "mock_model_unavailable"})
                    return
                finally:
                    connection.close()
                self.reply(response.status, response_body,
                           "text/plain" if response.status == 200 else "application/json")
                return
            connection = http.client.HTTPConnection("127.0.0.1", 9002, timeout=3)
            try:
                connection.request("POST", "/infer", body=raw,
                                   headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                response_body = response.read()
            except OSError:
                self.json_reply(502, {"status": "mock_backend_unavailable"})
                return
            finally:
                connection.close()
            self.reply(response.status, response_body,
                       "text/plain" if response.status == 200 else "application/json")
            return

        if MODE == "backend":
            raw = self.rfile.read(min(int(self.headers.get("Content-Length", "0")), LIMIT + 1))
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.json_reply(400, {"status": "invalid_json"})
                return
            if type(value) is not dict or value.get("request_id") not in {
                POLICY["fixtures"]["valid"]["request_id"], POLICY["fixtures"]["schema_invalid"]["request_id"],
                "fixture-0902-003-size",
            }:
                self.json_reply(422, {"status": "unknown_fixture"})
                return
            backend_calls += 1
            last_request_id = value["request_id"]
            self.reply(200, MARKER, "text/plain")
            return
        self.json_reply(500, {"status": "invalid_fixture_mode"})


PORT = {"gateway": 8080, "model": 9001, "backend": 9002}[MODE]
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
